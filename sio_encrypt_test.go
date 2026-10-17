package sio_test

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// Encrypt

func TestEncrypt_ValidConfig(t *testing.T) {
	for _, tt := range validConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.Encrypt(io.Discard, bytes.NewReader(testData(1)), tt.config)
			assert.NoError(t, err)
		})
	}
}

func TestEncrypt_InvalidConfig(t *testing.T) {
	for _, tt := range invalidConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.Encrypt(io.Discard, bytes.NewReader(testData(1)), tt.config)
			assert.Error(t, err)
		})
	}
}

func TestEncrypt_FailingRand(t *testing.T) {
	// Sin Nonce, el nonce se lee de Config.Rand. Mocks de Rand que fallan o no
	// dan bytes suficientes deben producir un error.
	for _, v := range versions {
		for _, r := range failingRands {
			t.Run(v.name+"/"+r.name, func(t *testing.T) {
				config := v.config
				config.Nonce, config.Rand = nil, r.rand(v.randSize)
				_, err := sio.Encrypt(io.Discard, bytes.NewReader(testData(1)), config)
				assert.Error(t, err)
			})
		}
	}
}

func TestEncrypt_Golden(t *testing.T) {
	// Con clave y nonce fijos, la salida es exactamente la de testdata/gen.py.
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				dst := bytes.NewBuffer([]byte{})
				_, err := sio.Encrypt(dst, bytes.NewReader(testData(s.size)), v.config)
				assert.Equal(t, outcome[[]byte]{golden(v.name, s.size), nil}, outcome[[]byte]{dst.Bytes(), err})
			})
		}
	}
}

func TestEncrypt_ByteCount(t *testing.T) {
	// Doc de Encrypt: devuelve el número de bytes escritos en dst.
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				n, err := sio.Encrypt(io.Discard, bytes.NewReader(testData(s.size)), v.config)
				assert.Equal(t, outcome[int64]{int64(len(golden(v.name, s.size))), nil}, outcome[int64]{n, err})
			})
		}
	}
}

func TestEncrypt_RandomSizes(t *testing.T) {
	// Datos aleatorios: DARE.md, sección 3, cada paquete de hasta 64 KiB
	// añade 32 bytes (cabecera y tag).
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.SampledFrom(versions).Draw(t, "version")
		size := rapid.IntRange(0, 3*maxPayloadSize).Draw(t, "size")
		packages := (size + maxPayloadSize - 1) / maxPayloadSize
		n, err := sio.Encrypt(io.Discard, bytes.NewReader(testData(size)), v.config)
		assert.Equal(t, outcome[int64]{int64(size + packages*overhead), nil}, outcome[int64]{n, err})
	})
}

func TestEncrypt_VersionInRange(t *testing.T) {
	for _, tt := range versionRanges {
		t.Run(tt.name, func(t *testing.T) {
			config := sio.Config{Key: make([]byte, 32), MinVersion: tt.min, MaxVersion: tt.max}
			dst := bytes.NewBuffer([]byte{})
			_, err := sio.Encrypt(dst, bytes.NewReader(testData(1)), config)
			assert.Equal(t, outcome[[]byte]{[]byte{tt.header}, nil}, outcome[[]byte]{dst.Bytes()[:min(1, dst.Len())], err})
		})
	}
}

func TestEncrypt_NoVersionInRange(t *testing.T) {
	// Ni la 1.0 ni la 2.0 están en el rango, así que cifrar debe dar error.
	for _, tt := range rangesWithoutVersion {
		t.Run(tt.name, func(t *testing.T) {
			config := sio.Config{Key: make([]byte, 32), MinVersion: tt.min, MaxVersion: tt.max}
			_, err := sio.Encrypt(io.Discard, bytes.NewReader(testData(1)), config)
			assert.Error(t, err)
		})
	}
}

func TestEncrypt_SourceError(t *testing.T) {
	// Mock de src que falla después de entregar algunos bytes: el error
	// debe llegar al que llama.
	errSource := errors.New("source failed")
	prefixes := []struct {
		name string
		size int
	}{
		{"at start", 0},
		{"after one byte", 1},
		{"after one full package", maxPayloadSize},
		{"after one byte more than a full package", maxPayloadSize + 1},
	}
	for _, v := range versions {
		for _, p := range prefixes {
			t.Run(v.name+"/"+p.name, func(t *testing.T) {
				src := io.MultiReader(bytes.NewReader(testData(p.size)), iotest.ErrReader(errSource))
				_, err := sio.Encrypt(io.Discard, src, v.config)
				assert.ErrorIs(t, err, errSource)
			})
		}
	}
}

func TestEncrypt_DestinationError(t *testing.T) {
	// Mock de dst que falla a partir de un byte de la salida cifrada.
	errDestination := errors.New("destination failed")
	failures := []struct {
		name   string
		failAt int
	}{
		{"at start", 0},
		{"inside the first package", maxPackageSize / 2},
		{"inside the second package", maxPackageSize + 1},
	}
	for _, v := range versions {
		for _, f := range failures {
			t.Run(v.name+"/"+f.name, func(t *testing.T) {
				dst := &failingWriter{failAt: f.failAt, err: errDestination}
				_, err := sio.Encrypt(dst, bytes.NewReader(testData(maxPayloadSize+1)), v.config)
				assert.ErrorIs(t, err, errDestination)
			})
		}
	}
}
