package sio_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
	"testing/iotest"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// EncryptReader

func TestEncryptReader_ValidConfig(t *testing.T) {
	for _, tt := range validConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.EncryptReader(bytes.NewReader(nil), tt.config)
			assert.NoError(t, err)
		})
	}
}

func TestEncryptReader_InvalidConfig(t *testing.T) {
	for _, tt := range invalidConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.EncryptReader(bytes.NewReader(nil), tt.config)
			assert.Error(t, err)
		})
	}
}

func TestEncryptReader_RandomKeySizes(t *testing.T) {
	// Datos aleatorios: solo las claves de 16 y 32 bytes son válidas.
	rapid.Check(t, func(t *rapid.T) {
		size := rapid.IntRange(0, 128).Draw(t, "key size")
		_, err := sio.EncryptReader(bytes.NewReader(nil), sio.Config{Key: make([]byte, size)})
		assert.Equal(t, size == 16 || size == 32, err == nil)
	})
}

func TestEncryptReader_FailingRand(t *testing.T) {
	// Sin Nonce, el nonce se lee de Config.Rand. Mocks de Rand que fallan o no
	// dan bytes suficientes deben producir un error.
	rands := []struct {
		name string
		rand func(size int) io.Reader
	}{
		{"read error", func(int) io.Reader { return iotest.ErrReader(errors.New("rand failed")) }},
		{"empty", func(int) io.Reader { return bytes.NewReader(nil) }},
		{"one byte short", func(size int) io.Reader { return bytes.NewReader(make([]byte, size-1)) }},
	}
	for _, v := range versions {
		for _, r := range rands {
			t.Run(v.name+"/"+r.name, func(t *testing.T) {
				config := v.config
				config.Nonce, config.Rand = nil, r.rand(v.randSize)
				_, err := sio.EncryptReader(bytes.NewReader(nil), config)
				assert.Error(t, err)
			})
		}
	}
}

func TestEncryptReader_Golden(t *testing.T) {
	// Con clave y nonce fijos, la salida es exactamente la de testdata/gen.py.
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				got, err := encrypt(bytes.NewReader(testData(s.size)), v.config, 0)
				assert.Equal(t, outcome[[]byte]{golden(v.name, s.size), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestEncryptReader_HeaderBytes(t *testing.T) {
	// DARE.md, sección 3: el byte 0 es la versión y el byte 1 el cifrado.
	for _, v := range versions {
		for _, c := range cipherSuites {
			t.Run(v.name+"/"+c.name, func(t *testing.T) {
				config := v.config
				config.CipherSuites = []byte{c.suite}
				out, err := encrypt(bytes.NewReader(testData(1)), config, 0)
				assert.Equal(t, outcome[[]byte]{[]byte{v.header, c.header}, nil}, outcome[[]byte]{out[:min(2, len(out))], err})
			})
		}
	}
}

func TestEncryptReader_AnyReadSize(t *testing.T) {
	// La salida no depende del tamaño del buffer de lectura.
	// Fronteras: 1 byte, la cabecera, un paquete completo y ±1.
	bufSizes := []int{1, headerSize, maxPackageSize - 1, maxPackageSize, maxPackageSize + 1}
	for _, v := range versions {
		for _, size := range bufSizes {
			t.Run(fmt.Sprintf("%s/buffer %d", v.name, size), func(t *testing.T) {
				got, err := encrypt(bytes.NewReader(testData(maxPayloadSize+1)), v.config, size)
				assert.Equal(t, outcome[[]byte]{golden(v.name, maxPayloadSize+1), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestEncryptReader_SlowSource(t *testing.T) {
	// Mocks de src que entregan los datos a trozos: la salida no cambia.
	sources := []struct {
		name string
		wrap func(io.Reader) io.Reader
	}{
		{"one byte per read", iotest.OneByteReader},
		{"half of each read", iotest.HalfReader},
		{"data and EOF together", iotest.DataErrReader},
	}
	for _, v := range versions {
		for _, s := range sources {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				got, err := encrypt(s.wrap(bytes.NewReader(testData(maxPayloadSize+1))), v.config, 0)
				assert.Equal(t, outcome[[]byte]{golden(v.name, maxPayloadSize+1), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestEncryptReader_SourceError(t *testing.T) {
	// Mock de src que falla después de entregar algunos bytes: el error
	// debe llegar al que lee.
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
				_, err := encrypt(src, v.config, 0)
				assert.ErrorIs(t, err, errSource)
			})
		}
	}
}
