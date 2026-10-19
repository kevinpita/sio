package sio_test

// Datos de prueba compartidos por todos los archivos de pruebas: particiones,
// valores frontera, configuraciones y salidas cifradas de referencia.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"testing/iotest"

	"github.com/minio/sio"
)

// testData devuelve n bytes con la secuencia 0, 1, 2, ..., 250, 0, 1, ...
// 251 no divide 64 KiB: paquetes cercanos empiezan en valores distintos, así que
// desplazar unos bytes o repetir o cambiar de orden esos paquetes se detecta.
func testData(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i % 251)
	}
	return data
}

// fixedNonce sustituye al nonce aleatorio (Config.Nonce). Con el mismo nonce y
// la misma clave, el cifrado da siempre los mismos bytes, así que dos salidas
// se pueden comparar byte a byte.
var fixedNonce = [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

// Una configuración por versión. El cifrado es fijo (AES-GCM) para que la
// salida no dependa del procesador.
var versions = []struct {
	name     string
	header   byte // valor del byte 0 de la cabecera
	randSize int  // bytes que se leen de Config.Rand (V1.0: 8, V2.0: 12)
	config   sio.Config
}{
	{"1.0", 0x10, 8, sio.Config{
		Key: make([]byte, 32), MinVersion: sio.Version10, MaxVersion: sio.Version10,
		CipherSuites: []byte{sio.AES_GCM}, Nonce: &fixedNonce,
	}},
	{"2.0", 0x20, 12, sio.Config{
		Key: make([]byte, 32), MinVersion: sio.Version20, MaxVersion: sio.Version20,
		CipherSuites: []byte{sio.AES_GCM}, Nonce: &fixedNonce,
	}},
}

// Configuración por defecto: solo la clave (doc de Config). Admite la 1.0 y la
// 2.0, así que al descifrar detecta la versión de los datos.
var defaultConfig = sio.Config{Key: make([]byte, 32)}

// Configuraciones que admiten una sola versión (doc de Config: MinVersion y
// MaxVersion son la versión mínima y máxima admitidas).
var (
	onlyVersion10 = sio.Config{Key: make([]byte, 32), MinVersion: sio.Version10, MaxVersion: sio.Version10}
	onlyVersion20 = sio.Config{Key: make([]byte, 32), MinVersion: sio.Version20, MaxVersion: sio.Version20}
)

// Cifrados y su valor en el byte 1 de la cabecera según DARE.md.
var cipherSuites = []struct {
	name   string
	suite  byte
	header byte
}{
	{"AES-GCM", sio.AES_GCM, 0x00},
	{"ChaCha20-Poly1305", sio.CHACHA20_POLY1305, 0x01},
}

// Particiones del tamaño del texto plano y sus fronteras.
var plaintextSizes = []struct {
	name string
	size int
}{
	{"empty stream", 0},
	{"one byte", 1},
	{"one byte less than a full package", maxPayloadSize - 1},
	{"one full package", maxPayloadSize},
	{"one byte more than a full package", maxPayloadSize + 1},
}

// Salidas de referencia (golden): testdata/v<versión>_<tamaño>.dare contiene
// testData(tamaño) cifrado con la configuración de esa versión. Las genera
// testdata/gen.py, que sigue DARE.md (1.0) y testdata/V2.md (2.0) sin usar sio.
func golden(version string, size int) []byte {
	data, err := os.ReadFile(fmt.Sprintf("testdata/v%s_%d.dare", version, size))
	if err != nil {
		panic(err) // falta el fichero: ejecutar testdata/gen.py
	}
	return data
}

// Configuraciones compartidas por todas las funciones públicas que reciben una
// Config. Solo incluyen reglas que la documentación aplica a cualquier
// función, para cifrar y para descifrar.

// validConfigs: configuraciones válidas. Ninguna función debe rechazarlas.
var validConfigs = []struct {
	name   string
	config sio.Config
}{
	// Solo la clave es obligatoria (doc de Config).
	{"defaults, 256-bit key", sio.Config{Key: make([]byte, 32)}},
	// Clave: 128 o 256 bits (doc de AES_GCM).
	{"128-bit key", sio.Config{Key: make([]byte, 16)}},
	// Cifrados: cada uno por separado y los dos.
	{"only AES-GCM", sio.Config{Key: make([]byte, 32), CipherSuites: []byte{sio.AES_GCM}}},
	{"only ChaCha20-Poly1305", sio.Config{Key: make([]byte, 32), CipherSuites: []byte{sio.CHACHA20_POLY1305}}},
	{"both cipher suites", sio.Config{Key: make([]byte, 32), CipherSuites: []byte{sio.AES_GCM, sio.CHACHA20_POLY1305}}},
	// PayloadSize: fronteras del rango de 1 byte a 64 KiB (doc de Config).
	{"smallest payload", sio.Config{Key: make([]byte, 32), PayloadSize: 1}},
	{"largest payload", sio.Config{Key: make([]byte, 32), PayloadSize: maxPayloadSize}},
	// MinVersion y MaxVersion: cada versión sola y el rango completo.
	{"only version 1.0", sio.Config{Key: make([]byte, 32), MinVersion: sio.Version10, MaxVersion: sio.Version10}},
	{"only version 2.0", sio.Config{Key: make([]byte, 32), MinVersion: sio.Version20, MaxVersion: sio.Version20}},
	{"versions 1.0 to 2.0", sio.Config{Key: make([]byte, 32), MinVersion: sio.Version10, MaxVersion: sio.Version20}},
}

// invalidConfigs: configuraciones no válidas. Toda función debe devolver error.
var invalidConfigs = []struct {
	name   string
	config sio.Config
}{
	// Clave: fuera de 128 y 256 bits. Fronteras a ±1 byte de cada tamaño válido.
	{"nil key", sio.Config{Key: nil}},
	{"empty key", sio.Config{Key: []byte{}}},
	{"key one byte less than 128 bits", sio.Config{Key: make([]byte, 15)}},
	{"key one byte more than 128 bits", sio.Config{Key: make([]byte, 17)}},
	{"192-bit key", sio.Config{Key: make([]byte, 24)}},
	{"key one byte less than 256 bits", sio.Config{Key: make([]byte, 31)}},
	{"key one byte more than 256 bits", sio.Config{Key: make([]byte, 33)}},
	// Cifrados: un valor que no es AES_GCM ni CHACHA20_POLY1305.
	{"cipher one more than the last known", sio.Config{Key: make([]byte, 32), CipherSuites: []byte{sio.CHACHA20_POLY1305 + 1}}},
	{"cipher largest byte", sio.Config{Key: make([]byte, 32), CipherSuites: []byte{math.MaxUint8}}},
	{"known and unknown cipher", sio.Config{Key: make([]byte, 32), CipherSuites: []byte{sio.AES_GCM, sio.CHACHA20_POLY1305 + 1}}},
	// PayloadSize: fuera del rango de 1 byte a 64 KiB (doc de Config).
	{"payload one byte more than 64 KiB", sio.Config{Key: make([]byte, 32), PayloadSize: maxPayloadSize + 1}},
	{"payload largest int", sio.Config{Key: make([]byte, 32), PayloadSize: math.MaxInt}},
	{"payload minus one", sio.Config{Key: make([]byte, 32), PayloadSize: -1}},
	{"payload smallest int", sio.Config{Key: make([]byte, 32), PayloadSize: math.MinInt}},
	// MinVersion y MaxVersion: el mínimo no puede ser mayor que el máximo.
	{"min version above max version", sio.Config{Key: make([]byte, 32), MinVersion: sio.Version20, MaxVersion: sio.Version10}},
}

// Alteraciones de un flujo de 2 paquetes (64 KiB y 1 byte). DARE.md, sección 2:
// un atacante no puede modificar ni eliminar paquetes sin que se detecte.
var tamperings = []struct {
	name   string
	tamper func(s []byte) []byte
}{
	{"version byte changed", func(s []byte) []byte { s[0] ^= 0xff; return s }},
	{"first payload byte changed", func(s []byte) []byte { s[headerSize] ^= 1; return s }},
	{"last byte changed", func(s []byte) []byte { s[len(s)-1] ^= 1; return s }},
	{"last byte removed", func(s []byte) []byte { return s[:len(s)-1] }},
	{"first package removed", func(s []byte) []byte { return s[maxPackageSize:] }},
}

// Rangos de versión que no incluyen la versión de los datos. Doc de Config:
// MinVersion y MaxVersion son la versión mínima y máxima admitidas.
var versionsOutsideRange = []struct {
	name     string
	data     string // versión de los datos
	min, max byte
}{
	{"1.0 data, min just above 1.0", "1.0", sio.Version10 + 1, sio.Version20},
	{"1.0 data, min just below 2.0", "1.0", sio.Version20 - 1, sio.Version20},
	{"1.0 data, min 2.0", "1.0", sio.Version20, sio.Version20},
	{"2.0 data, max 1.0", "2.0", sio.Version10, sio.Version10},
	{"2.0 data, max just below 2.0", "2.0", sio.Version10, sio.Version20 - 1},
}

// Alteraciones de un flujo de 2 paquetes (64 KiB y 1 byte) y el texto plano que
// se puede entregar: solo los paquetes anteriores al alterado.
var authenticatedPrefixes = []struct {
	name   string
	tamper func(s []byte) []byte
	want   []byte
}{
	{"first package changed", func(s []byte) []byte { s[headerSize] ^= 1; return s }, []byte{}},
	{"second package changed", func(s []byte) []byte { s[len(s)-1] ^= 1; return s }, testData(maxPayloadSize)},
	{"second package cut", func(s []byte) []byte { return s[:len(s)-1] }, testData(maxPayloadSize)},
}

// Mocks de Config.Rand que fallan o no dan los bytes que pide el nonce
// (versions.randSize).
var failingRands = []struct {
	name string
	rand func(size int) io.Reader
}{
	{"read error", func(int) io.Reader { return iotest.ErrReader(errors.New("rand failed")) }},
	{"empty", func(int) io.Reader { return bytes.NewReader(nil) }},
	{"one byte short", func(size int) io.Reader { return bytes.NewReader(make([]byte, size-1)) }},
}

// Rangos de versión para cifrar. Doc de Config: MinVersion y MaxVersion son la
// versión mínima y máxima admitidas, así que la salida debe usar una versión
// dentro del rango.
var versionRanges = []struct {
	name     string
	min, max byte
	header   byte // versión esperada en el byte 0
}{
	{"only 1.0", sio.Version10, sio.Version10, 0x10},
	{"1.0 to just below 2.0", sio.Version10, sio.Version20 - 1, 0x10},
	{"just above 1.0 to 2.0", sio.Version10 + 1, sio.Version20, 0x20},
	{"only 2.0", sio.Version20, sio.Version20, 0x20},
}

// Rangos de versión válidos para Config que no incluyen ni la 1.0 ni la 2.0:
// no se puede cifrar con una versión dentro del rango.
var rangesWithoutVersion = []struct {
	name     string
	min, max byte
}{
	{"just above 1.0 to just below 2.0", sio.Version10 + 1, sio.Version20 - 1},
	{"only just above 1.0", sio.Version10 + 1, sio.Version10 + 1},
	{"only just below 2.0", sio.Version20 - 1, sio.Version20 - 1},
}
