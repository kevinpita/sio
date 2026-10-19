package sio_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// Pruebas de integración: el que cifra y el que descifra se ponen de acuerdo
// a través de la Config. Se cifra con EncryptReader y se descifra con
// DecryptReader, cada uno con su propia configuración. Doc de DecryptReader:
// si el descifrado falla, el error es de tipo sio.Error.

// encryptThenDecrypt cifra plaintext con la configuración enc y descifra el
// resultado con dec. Cifrar es la preparación de la prueba: si falla, la
// prueba se para, así que el error devuelto siempre es del descifrado.
func encryptThenDecrypt(t *testing.T, plaintext []byte, enc, dec sio.Config) ([]byte, error) {
	t.Helper()
	stream, err := encrypt(bytes.NewReader(plaintext), enc, 0)
	if err != nil {
		t.Fatal(err)
	}
	return decrypt(bytes.NewReader(stream), dec, 0)
}

func TestIntegration_VersionInterop(t *testing.T) {
	// Los datos tienen una versión que el que descifra admite: se descifran.
	// La configuración por defecto admite la 1.0 y la 2.0.
	tests := []struct {
		name     string
		enc, dec sio.Config
	}{
		{"1.0 data, only 1.0", onlyVersion10, onlyVersion10},
		{"1.0 data, default", onlyVersion10, defaultConfig},
		{"2.0 data, only 2.0", onlyVersion20, onlyVersion20},
		{"2.0 data, default", onlyVersion20, defaultConfig},
		{"default data, default", defaultConfig, defaultConfig},
	}
	plaintext := testData(maxPayloadSize + 1)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptThenDecrypt(t, plaintext, tt.enc, tt.dec)
			assert.Equal(t, outcome[[]byte]{plaintext, nil}, outcome[[]byte]{got, err})
		})
	}
}

func TestIntegration_VersionMismatch(t *testing.T) {
	// Los datos tienen una versión que el que descifra no admite.
	tests := []struct {
		name     string
		enc, dec sio.Config
	}{
		{"1.0 data, only 2.0", onlyVersion10, onlyVersion20},
		{"2.0 data, only 1.0", onlyVersion20, onlyVersion10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptThenDecrypt(t, testData(1), tt.enc, tt.dec)
			assert.ErrorAs(t, err, new(sio.Error))
		})
	}
}

func TestIntegration_CipherMismatch(t *testing.T) {
	// Doc de Config: CipherSuites es la lista de cifrados admitidos. Si se
	// cifra con uno que el que descifra no admite, el descifrado falla.
	tests := []struct {
		name     string
		enc, dec byte
	}{
		{"AES-GCM data, only ChaCha20-Poly1305", sio.AES_GCM, sio.CHACHA20_POLY1305},
		{"ChaCha20-Poly1305 data, only AES-GCM", sio.CHACHA20_POLY1305, sio.AES_GCM},
	}
	for _, v := range versions {
		for _, tt := range tests {
			t.Run(v.name+"/"+tt.name, func(t *testing.T) {
				enc, dec := v.config, v.config
				enc.CipherSuites, dec.CipherSuites = []byte{tt.enc}, []byte{tt.dec}
				_, err := encryptThenDecrypt(t, testData(1), enc, dec)
				assert.ErrorAs(t, err, new(sio.Error))
			})
		}
	}
}

func TestIntegration_KeyMismatch(t *testing.T) {
	// Se descifra con otra clave de 32 bytes (doc de Config.Key): DARE.md,
	// sección 5, el tag no coincide y el descifrado falla. Fronteras: un solo
	// bit cambiado en el primer o en el último byte de la clave.
	key := testData(32)
	firstBit, lastBit := testData(32), testData(32)
	firstBit[0] ^= 1
	lastBit[31] ^= 1
	keys := []struct {
		name string
		key  []byte
	}{
		{"other key", make([]byte, 32)},
		{"one bit changed in the first byte", firstBit},
		{"one bit changed in the last byte", lastBit},
	}
	for _, v := range versions {
		for _, k := range keys {
			t.Run(v.name+"/"+k.name, func(t *testing.T) {
				enc, dec := v.config, v.config
				enc.Key, dec.Key = key, k.key
				_, err := encryptThenDecrypt(t, testData(1), enc, dec)
				assert.ErrorAs(t, err, new(sio.Error))
			})
		}
	}
}

func TestIntegration_SequenceNumber(t *testing.T) {
	// Doc de Config: SequenceNumber es el primer número de secuencia que se
	// espera, y solo se pone al descifrar un trozo de un flujo. Se cifra un
	// flujo de 3 paquetes y se descifra desde el paquete N hasta el final.
	plaintext := testData(2*maxPayloadSize + 1)
	for _, v := range versions {
		for _, n := range []uint32{0, 1, 2} {
			t.Run(fmt.Sprintf("%s/from package %d", v.name, n), func(t *testing.T) {
				var got []byte
				stream, err := encrypt(bytes.NewReader(plaintext), v.config, 0)
				if err == nil {
					config := v.config
					config.SequenceNumber = n
					got, err = decrypt(bytes.NewReader(stream[int(n)*maxPackageSize:]), config, 0)
				}
				assert.Equal(t, outcome[[]byte]{plaintext[int(n)*maxPayloadSize:], nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestIntegration_SequenceNumberMismatch(t *testing.T) {
	// El trozo empieza en el paquete N pero se espera otro número (±1): el
	// descifrado falla. DARE.md, sección 5: err_package_out_of_order.
	tests := []struct {
		name         string
		from, number uint32 // paquete donde empieza el trozo y número esperado
	}{
		{"from package 0, expecting 1", 0, 1},
		{"from package 1, expecting 0", 1, 0},
		{"from package 1, expecting 2", 1, 2},
		{"from package 2, expecting 1", 2, 1},
	}
	plaintext := testData(2*maxPayloadSize + 1)
	for _, v := range versions {
		for _, tt := range tests {
			t.Run(v.name+"/"+tt.name, func(t *testing.T) {
				stream, err := encrypt(bytes.NewReader(plaintext), v.config, 0)
				if err != nil {
					t.Fatal(err)
				}
				config := v.config
				config.SequenceNumber = tt.number
				_, err = decrypt(bytes.NewReader(stream[int(tt.from)*maxPackageSize:]), config, 0)
				assert.ErrorAs(t, err, new(sio.Error))
			})
		}
	}
}

func TestIntegration_RandomSequenceNumber(t *testing.T) {
	// Datos aleatorios: número de paquetes (de 1 a 4), tamaño del último
	// paquete y paquete desde el que se descifra. Un flujo vacío no tiene
	// paquetes desde los que empezar, así que no entra aquí.
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.SampledFrom(versions).Draw(t, "version")
		packages := rapid.Uint32Range(1, 4).Draw(t, "packages")
		size := rapid.IntRange(int(packages-1)*maxPayloadSize+1, int(packages)*maxPayloadSize).Draw(t, "size")
		n := rapid.Uint32Range(0, packages-1).Draw(t, "from package")
		plaintext := testData(size)
		var got []byte
		stream, err := encrypt(bytes.NewReader(plaintext), v.config, 0)
		if err == nil {
			config := v.config
			config.SequenceNumber = n
			got, err = decrypt(bytes.NewReader(stream[int(n)*maxPackageSize:]), config, 0)
		}
		assert.Equal(t, outcome[[]byte]{plaintext[int(n)*maxPayloadSize:], nil}, outcome[[]byte]{got, err})
	})
}
