package sio_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"
)

// Pruebas de integración: las funciones de tamaño frente al cifrado real.
// Doc de EncryptedSize y DecryptedSize: calculan el tamaño del flujo cifrado a
// partir del tamaño del texto plano, y al revés. Se cifra con Encrypt, y el
// tamaño real de la salida (y el del texto plano) es el valor esperado.

func TestIntegration_EncryptedSizeMatchesOutput(t *testing.T) {
	for _, v := range versions {
		for _, s := range roundTripSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				var got uint64
				n, err := sio.Encrypt(io.Discard, bytes.NewReader(testData(s.size)), v.config)
				if err == nil {
					got, err = sio.EncryptedSize(u64(s.size))
				}
				assert.Equal(t, outcome[uint64]{u64(n), nil}, outcome[uint64]{got, err})
			})
		}
	}
}

func TestIntegration_DecryptedSizeMatchesInput(t *testing.T) {
	for _, v := range versions {
		for _, s := range roundTripSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				var got uint64
				n, err := sio.Encrypt(io.Discard, bytes.NewReader(testData(s.size)), v.config)
				if err == nil {
					got, err = sio.DecryptedSize(u64(n))
				}
				assert.Equal(t, outcome[uint64]{u64(s.size), nil}, outcome[uint64]{got, err})
			})
		}
	}
}

// Doc de Config.PayloadSize (solo DARE 1.0): limita el tamaño de los paquetes
// cifrados, entre 1 byte y 64 KiB. Las funciones de tamaño no reciben la
// Config, y su doc no pone ninguna condición. Fronteras del rango de
// PayloadSize y un valor intermedio. El texto plano ocupa 2 paquetes de 64 KiB.
var payloadSizes = []int{1, 1000, maxPayloadSize - 1, maxPayloadSize}

const payloadSizePlaintext = 2 * maxPayloadSize

func TestIntegration_EncryptedSizeWithPayloadSize(t *testing.T) {
	for _, p := range payloadSizes {
		t.Run(fmt.Sprintf("payload %d", p), func(t *testing.T) {
			config := onlyVersion10
			config.PayloadSize = p
			var got uint64
			n, err := sio.Encrypt(io.Discard, bytes.NewReader(testData(payloadSizePlaintext)), config)
			if err == nil {
				got, err = sio.EncryptedSize(payloadSizePlaintext)
			}
			assert.Equal(t, outcome[uint64]{u64(n), nil}, outcome[uint64]{got, err})
		})
	}
}

func TestIntegration_DecryptedSizeWithPayloadSize(t *testing.T) {
	for _, p := range payloadSizes {
		t.Run(fmt.Sprintf("payload %d", p), func(t *testing.T) {
			config := onlyVersion10
			config.PayloadSize = p
			var got uint64
			n, err := sio.Encrypt(io.Discard, bytes.NewReader(testData(payloadSizePlaintext)), config)
			if err == nil {
				got, err = sio.DecryptedSize(u64(n))
			}
			assert.Equal(t, outcome[uint64]{payloadSizePlaintext, nil}, outcome[uint64]{got, err})
		})
	}
}

// u64 pasa un tamaño a uint64, el tipo de EncryptedSize y DecryptedSize. En
// estas pruebas los tamaños nunca son negativos.
func u64[T int | int64](n T) uint64 { return uint64(n) } //nolint:gosec // n >= 0
