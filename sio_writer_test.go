package sio_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// EncryptWriter

func TestEncryptWriter_ValidConfig(t *testing.T) {
	for _, tt := range validConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.EncryptWriter(&bytes.Buffer{}, tt.config)
			assert.NoError(t, err)
		})
	}
}

func TestEncryptWriter_InvalidConfig(t *testing.T) {
	for _, tt := range invalidConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.EncryptWriter(&bytes.Buffer{}, tt.config)
			assert.Error(t, err)
		})
	}
}

func TestEncryptWriter_FailingRand(t *testing.T) {
	// Sin Nonce, el nonce se lee de Config.Rand. Mocks de Rand que fallan o no
	// dan bytes suficientes deben producir un error.
	for _, v := range versions {
		for _, r := range failingRands {
			t.Run(v.name+"/"+r.name, func(t *testing.T) {
				config := v.config
				config.Nonce, config.Rand = nil, r.rand(v.randSize)
				_, err := encryptW(testData(1), config, 0)
				assert.Error(t, err)
			})
		}
	}
}

func TestEncryptWriter_Golden(t *testing.T) {
	// Con clave y nonce fijos, la salida es exactamente la de testdata/gen.py.
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				got, err := encryptW(testData(s.size), v.config, 0)
				assert.Equal(t, outcome[[]byte]{golden(v.name, s.size), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestEncryptWriter_HeaderBytes(t *testing.T) {
	// DARE.md, sección 3: el byte 0 es la versión y el byte 1 el cifrado.
	for _, v := range versions {
		for _, c := range cipherSuites {
			t.Run(v.name+"/"+c.name, func(t *testing.T) {
				config := v.config
				config.CipherSuites = []byte{c.suite}
				out, err := encryptW(testData(1), config, 0)
				assert.Equal(t, outcome[[]byte]{[]byte{v.header, c.header}, nil}, outcome[[]byte]{out[:min(2, len(out))], err})
			})
		}
	}
}

func TestEncryptWriter_AnyWriteSize(t *testing.T) {
	// La salida no depende del tamaño de cada Write.
	// Fronteras: 1 byte y un payload completo ±1.
	writeSizes := []int{1, maxPayloadSize - 1, maxPayloadSize, maxPayloadSize + 1}
	for _, v := range versions {
		for _, size := range writeSizes {
			t.Run(fmt.Sprintf("%s/write %d", v.name, size), func(t *testing.T) {
				got, err := encryptW(testData(maxPayloadSize+1), v.config, size)
				assert.Equal(t, outcome[[]byte]{golden(v.name, maxPayloadSize+1), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestEncryptWriter_RandomWriteSizes(t *testing.T) {
	// Datos aleatorios: escribir el texto plano en trozos de tamaño aleatorio
	// da la misma salida.
	plaintext := testData(maxPayloadSize + 1)
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.SampledFrom(versions).Draw(t, "version")
		out := &bytes.Buffer{}
		w, err := sio.EncryptWriter(out, v.config)
		for src := plaintext; err == nil && len(src) > 0; {
			n := rapid.IntRange(1, len(src)).Draw(t, "write size")
			_, err = w.Write(src[:n])
			src = src[n:]
		}
		if err == nil {
			err = w.Close()
		}
		assert.Equal(t, outcome[[]byte]{golden(v.name, len(plaintext)), nil}, outcome[[]byte]{out.Bytes(), err})
	})
}

func TestEncryptWriter_VersionInRange(t *testing.T) {
	for _, tt := range versionRanges {
		t.Run(tt.name, func(t *testing.T) {
			config := sio.Config{Key: make([]byte, 32), MinVersion: tt.min, MaxVersion: tt.max}
			out, err := encryptW(testData(1), config, 0)
			assert.Equal(t, outcome[[]byte]{[]byte{tt.header}, nil}, outcome[[]byte]{out[:min(1, len(out))], err})
		})
	}
}

func TestEncryptWriter_NoVersionInRange(t *testing.T) {
	// Ni la 1.0 ni la 2.0 están en el rango, así que cifrar debe dar error.
	for _, tt := range rangesWithoutVersion {
		t.Run(tt.name, func(t *testing.T) {
			config := sio.Config{Key: make([]byte, 32), MinVersion: tt.min, MaxVersion: tt.max}
			_, err := encryptW(testData(1), config, 0)
			assert.Error(t, err)
		})
	}
}

func TestEncryptWriter_DestinationError(t *testing.T) {
	// Mock de dst que falla a partir de un byte de la salida cifrada: el error
	// debe llegar al que escribe, en Write o en Close.
	errDestination := errors.New("destination failed")
	failures := []struct {
		name   string
		failAt int
	}{
		{"at start", 0},
		{"inside the first header", headerSize / 2},
		{"after one full package", maxPackageSize},
		{"inside the second package", maxPackageSize + headerSize + 1},
	}
	for _, v := range versions {
		for _, f := range failures {
			t.Run(v.name+"/"+f.name, func(t *testing.T) {
				w, err := sio.EncryptWriter(&failingWriter{failAt: f.failAt, err: errDestination}, v.config)
				if err == nil {
					err = writeAll(w, testData(maxPayloadSize+1), 0)
				}
				assert.ErrorIs(t, err, errDestination)
			})
		}
	}
}
