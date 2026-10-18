package sio_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// Error
//
// Doc de Error: es el error que se devuelve si los datos cifrados no se pueden
// descifrar porque están mal formados o no son auténticos. La doc no dice qué
// mensaje tiene, así que solo se comprueba que se devuelve y que el mensaje no
// está vacío. sio.Error{} se puede crear, pero la doc no dice nada de su valor
// cero, así que no hay valor esperado para él.

// Las dos particiones de la doc: datos mal formados y datos no auténticos.
var decryptionFailures = []struct {
	name   string
	tamper func(s []byte) []byte
}{
	{"malformed: version byte changed", func(s []byte) []byte { s[0] ^= 0xff; return s }},
	{"malformed: last byte removed", func(s []byte) []byte { return s[:len(s)-1] }},
	{"not authentic: first payload byte changed", func(s []byte) []byte { s[headerSize] ^= 1; return s }},
	{"not authentic: last byte changed", func(s []byte) []byte { s[len(s)-1] ^= 1; return s }},
}

func TestError_Returned(t *testing.T) {
	for _, v := range versions {
		for _, tt := range decryptionFailures {
			t.Run(v.name+"/"+tt.name, func(t *testing.T) {
				_, err := decrypt(bytes.NewReader(tt.tamper(golden(v.name, maxPayloadSize+1))), v.config, 0)
				assert.ErrorAs(t, err, new(sio.Error))
			})
		}
	}
}

func TestError_Message(t *testing.T) {
	for _, v := range versions {
		for _, tt := range decryptionFailures {
			t.Run(v.name+"/"+tt.name, func(t *testing.T) {
				_, err := decrypt(bytes.NewReader(tt.tamper(golden(v.name, maxPayloadSize+1))), v.config, 0)
				var sioErr sio.Error
				errors.As(err, &sioErr)
				assert.NotEmpty(t, sioErr.Error())
			})
		}
	}
}

func TestError_RandomTamperedByte(t *testing.T) {
	// Datos aleatorios: cualquier byte cambiado da un sio.Error.
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.SampledFrom(versions).Draw(t, "version")
		stream := golden(v.name, maxPayloadSize+1)
		pos := rapid.IntRange(0, len(stream)-1).Draw(t, "position")
		stream[pos] ^= rapid.ByteRange(1, 255).Draw(t, "xor")
		_, err := decrypt(bytes.NewReader(stream), v.config, 0)
		assert.ErrorAs(t, err, new(sio.Error))
	})
}
