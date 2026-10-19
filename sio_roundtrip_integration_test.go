package sio_test

import (
	"bytes"
	"math"
	"testing"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// Pruebas de integración: lo que cifra una función pública lo descifra
// cualquier otra. Las funciones cooperan a través del formato DARE, así que
// un error de formato en un lado aparece al descifrar en el otro. El valor
// esperado es siempre el texto plano original.

// Las 3 funciones públicas que cifran.
var encrypters = []struct {
	name    string
	encrypt func(plaintext []byte, config sio.Config) ([]byte, error)
}{
	{"Encrypt", func(p []byte, c sio.Config) ([]byte, error) {
		dst := bytes.NewBuffer([]byte{})
		_, err := sio.Encrypt(dst, bytes.NewReader(p), c)
		return dst.Bytes(), err
	}},
	{"EncryptReader", func(p []byte, c sio.Config) ([]byte, error) { return encrypt(bytes.NewReader(p), c, 0) }},
	{"EncryptWriter", func(p []byte, c sio.Config) ([]byte, error) { return encryptW(p, c, 0) }},
}

// Las 5 funciones públicas que descifran.
var decrypters = []struct {
	name    string
	decrypt func(stream []byte, config sio.Config) ([]byte, error)
}{
	{"Decrypt", func(s []byte, c sio.Config) ([]byte, error) {
		dst := bytes.NewBuffer([]byte{})
		_, err := sio.Decrypt(dst, bytes.NewReader(s), c)
		return dst.Bytes(), err
	}},
	{"DecryptReader", func(s []byte, c sio.Config) ([]byte, error) { return decrypt(bytes.NewReader(s), c, 0) }},
	{"DecryptReaderAt", func(s []byte, c sio.Config) ([]byte, error) { return decryptAt(s, c, 0, math.MaxInt) }},
	{"DecryptWriter", func(s []byte, c sio.Config) ([]byte, error) { return decryptW(s, c, 0) }},
	{"DecryptBuffer", func(s []byte, c sio.Config) ([]byte, error) { return sio.DecryptBuffer([]byte{}, s, c) }},
}

// Tamaños del texto plano: las fronteras de un paquete y un flujo de 3
// paquetes, para que haya un paquete en medio.
var roundTripSizes = []struct {
	name string
	size int
}{
	{"empty stream", 0},
	{"one byte", 1},
	{"one byte less than a full package", maxPayloadSize - 1},
	{"one full package", maxPayloadSize},
	{"one byte more than a full package", maxPayloadSize + 1},
	{"three packages", 2*maxPayloadSize + 1},
}

func TestIntegration_EncryptThenDecrypt(t *testing.T) {
	// Cada par cifrador × descifrador, con la misma configuración.
	for _, v := range versions {
		for _, e := range encrypters {
			for _, d := range decrypters {
				for _, s := range roundTripSizes {
					t.Run(v.name+"/"+e.name+"/"+d.name+"/"+s.name, func(t *testing.T) {
						var got []byte
						stream, err := e.encrypt(testData(s.size), v.config)
						if err == nil {
							got, err = d.decrypt(stream, v.config)
						}
						assert.Equal(t, outcome[[]byte]{testData(s.size), nil}, outcome[[]byte]{got, err})
					})
				}
			}
		}
	}
}

func TestIntegration_RandomRoundTrip(t *testing.T) {
	// Datos aleatorios: versión, par de funciones y tamaño. El flujo vacío ya
	// está en la tabla de TestIntegration_EncryptThenDecrypt, así que aquí el
	// tamaño empieza en 1 byte.
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.SampledFrom(versions).Draw(t, "version")
		e := rapid.SampledFrom(encrypters).Draw(t, "encrypter")
		d := rapid.SampledFrom(decrypters).Draw(t, "decrypter")
		plaintext := testData(rapid.IntRange(1, 3*maxPayloadSize).Draw(t, "size"))
		var got []byte
		stream, err := e.encrypt(plaintext, v.config)
		if err == nil {
			got, err = d.decrypt(stream, v.config)
		}
		assert.Equal(t, outcome[[]byte]{plaintext, nil}, outcome[[]byte]{got, err})
	})
}

func TestIntegration_CipherSuitesRoundTrip(t *testing.T) {
	// Se cifra con un solo cifrado y se descifra con la configuración por
	// defecto, que admite los dos (doc de Config). Tamaños de clave según la
	// doc de cada constante: AES_GCM con 128 o 256 bits, CHACHA20_POLY1305
	// con 256 bits.
	ciphers := []struct {
		name    string
		suite   byte
		keySize int
	}{
		{"AES-GCM/128-bit key", sio.AES_GCM, 16},
		{"AES-GCM/256-bit key", sio.AES_GCM, 32},
		{"ChaCha20-Poly1305/256-bit key", sio.CHACHA20_POLY1305, 32},
	}
	plaintext := testData(maxPayloadSize + 1)
	for _, v := range versions {
		for _, c := range ciphers {
			t.Run(v.name+"/"+c.name, func(t *testing.T) {
				config := v.config
				config.Key, config.CipherSuites = testData(c.keySize), []byte{c.suite}
				var got []byte
				stream, err := encrypt(bytes.NewReader(plaintext), config, 0)
				if err == nil {
					got, err = decrypt(bytes.NewReader(stream), sio.Config{Key: testData(c.keySize)}, 0)
				}
				assert.Equal(t, outcome[[]byte]{plaintext, nil}, outcome[[]byte]{got, err})
			})
		}
	}
}
