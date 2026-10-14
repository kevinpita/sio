package sio_test

import (
	"errors"
	"math"
	"testing"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// EncryptedSize

func TestEncryptedSize_ValidSizes(t *testing.T) {
	tests := []struct {
		name      string
		plaintext uint64
		want      uint64
	}{
		{"empty stream", 0, 0},
		{"one byte", 1, 1 + overhead},
		{"partial package", 1000, 1000 + overhead},
		// El paquete parcial más grande.
		{"one byte less than a full package", maxPayloadSize - 1, maxPayloadSize - 1 + overhead},
		{"one full package", maxPayloadSize, maxPackageSize},
		{"one byte more than a full package", maxPayloadSize + 1, maxPackageSize + 1 + overhead},
		{"full package and partial package", maxPayloadSize + 1000, maxPackageSize + 1000 + overhead},
		{"two full packages", 2 * maxPayloadSize, 2 * maxPackageSize},
		{"one byte less than maximum", maxPlaintextSize - 1, maxCiphertextSize - 1},
		{"maximum", maxPlaintextSize, maxCiphertextSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sio.EncryptedSize(tt.plaintext)
			assert.Equal(t, outcome[uint64]{tt.want, nil}, outcome[uint64]{got, err})
		})
	}
}

func TestEncryptedSize_TooLarge(t *testing.T) {
	// Partición: tamaños por encima del máximo del flujo (2^48 bytes).
	tests := []struct {
		name      string
		plaintext uint64
	}{
		{"one byte more than maximum", maxPlaintextSize + 1},
		{"one package more than maximum", maxPlaintextSize + maxPayloadSize},
		{"largest uint64", math.MaxUint64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.EncryptedSize(tt.plaintext)
			assert.Error(t, err)
		})
	}
}

func TestEncryptedSize_RandomTooLarge(t *testing.T) {
	// Datos aleatorios: cualquier tamaño por encima del máximo debe dar error.
	rapid.Check(t, func(t *rapid.T) {
		plaintext := rapid.Uint64Range(maxPlaintextSize+1, math.MaxUint64).Draw(t, "plaintext")
		_, err := sio.EncryptedSize(plaintext)
		assert.Error(t, err)
	})
}

// DecryptedSize

func TestDecryptedSize_ValidSizes(t *testing.T) {
	// Técnicas: particiones equivalentes y valores frontera (ver cada caso).
	// El valor esperado es el tamaño cifrado menos 32 bytes (overhead) por paquete.
	tests := []struct {
		name       string
		ciphertext uint64
		want       uint64
	}{
		{"empty stream", 0, 0},
		{"smallest package", 1 + overhead, 1},
		{"one full package", maxPackageSize, maxPayloadSize},
		{"full package and smallest package", maxPackageSize + 1 + overhead, maxPayloadSize + 1},
		{"two full packages", 2 * maxPackageSize, 2 * maxPayloadSize},
		{"maximum", maxCiphertextSize, maxPlaintextSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sio.DecryptedSize(tt.ciphertext)
			assert.Equal(t, outcome[uint64]{tt.want, nil}, outcome[uint64]{got, err})
		})
	}
}

func TestDecryptedSize_PackageWithoutPayload(t *testing.T) {
	// El último paquete debe tener al menos 1 byte de payload. Con overhead
	// bytes (solo cabecera y tag) o menos, el tamaño no es válido.
	tests := []struct {
		name       string
		ciphertext uint64
	}{
		{"one byte", 1},
		{"one byte less than header and tag", overhead - 1},
		{"only header and tag", overhead},
		{"full package and only header and tag", maxPackageSize + overhead},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.DecryptedSize(tt.ciphertext)
			assert.Error(t, err)
		})
	}
}

func TestDecryptedSize_TooLarge(t *testing.T) {
	tests := []struct {
		name       string
		ciphertext uint64
	}{
		{"one byte more than maximum", maxCiphertextSize + 1},
		{"one package more than maximum", maxCiphertextSize + maxPackageSize},
		{"largest uint64", math.MaxUint64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.DecryptedSize(tt.ciphertext)
			assert.Error(t, err)
		})
	}
}

func TestDecryptedSize_RandomInverseOfEncryptedSize(t *testing.T) {
	// Datos aleatorios: DecryptedSize debe deshacer EncryptedSize para
	// cualquier tamaño válido.
	rapid.Check(t, func(t *rapid.T) {
		plaintext := rapid.Uint64Range(0, maxPlaintextSize).Draw(t, "plaintext")
		ciphertext, encErr := sio.EncryptedSize(plaintext)
		got, decErr := sio.DecryptedSize(ciphertext)
		assert.Equal(t, outcome[uint64]{plaintext, nil}, outcome[uint64]{got, errors.Join(encErr, decErr)})
	})
}
