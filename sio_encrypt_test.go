package sio_test

import (
	"bytes"
	"io"
	"testing"

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
