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

// Decrypt
//
// La entrada son las salidas de referencia de testdata y el resultado
// esperado es el texto plano conocido, testData(tamaño).

func TestDecrypt_ValidConfig(t *testing.T) {
	// Con una configuración válida, unos datos que no son DARE (byte de versión
	// 0x00) solo pueden fallar al descifrar: error de tipo sio.Error (doc de
	// Decrypt). Un error de configuración no es de ese tipo.
	for _, tt := range validConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.Decrypt(io.Discard, bytes.NewReader(testData(overhead+1)), tt.config)
			assert.ErrorAs(t, err, new(sio.Error))
		})
	}
}

func TestDecrypt_InvalidConfig(t *testing.T) {
	// Los datos son un flujo DARE 1.0 válido para la clave a cero: el error
	// solo puede venir de la configuración.
	for _, tt := range invalidConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.Decrypt(io.Discard, bytes.NewReader(golden("1.0", 1)), tt.config)
			assert.Error(t, err)
		})
	}
}

func TestDecrypt_Golden(t *testing.T) {
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				dst := bytes.NewBuffer([]byte{})
				_, err := sio.Decrypt(dst, bytes.NewReader(golden(v.name, s.size)), v.config)
				assert.Equal(t, outcome[[]byte]{testData(s.size), nil}, outcome[[]byte]{dst.Bytes(), err})
			})
		}
	}
}

func TestDecrypt_ByteCount(t *testing.T) {
	// Doc de Decrypt: devuelve el número de bytes escritos en dst.
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				n, err := sio.Decrypt(io.Discard, bytes.NewReader(golden(v.name, s.size)), v.config)
				assert.Equal(t, outcome[int64]{int64(s.size), nil}, outcome[int64]{n, err})
			})
		}
	}
}

func TestDecrypt_Tampered(t *testing.T) {
	// Doc de Decrypt: si el descifrado falla, el error es de tipo sio.Error.
	for _, v := range versions {
		for _, tt := range tamperings {
			t.Run(v.name+"/"+tt.name, func(t *testing.T) {
				stream := tt.tamper(golden(v.name, maxPayloadSize+1))
				_, err := sio.Decrypt(io.Discard, bytes.NewReader(stream), v.config)
				assert.ErrorAs(t, err, new(sio.Error))
			})
		}
	}
}

func TestDecrypt_RandomTamperedByte(t *testing.T) {
	// Datos aleatorios: cambiar cualquier byte del flujo hace fallar el descifrado.
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.SampledFrom(versions).Draw(t, "version")
		stream := golden(v.name, maxPayloadSize+1)
		pos := rapid.IntRange(0, len(stream)-1).Draw(t, "position")
		stream[pos] ^= rapid.ByteRange(1, 255).Draw(t, "xor")
		_, err := sio.Decrypt(io.Discard, bytes.NewReader(stream), v.config)
		assert.ErrorAs(t, err, new(sio.Error))
	})
}

func TestDecrypt_OnlyAuthenticatedOutput(t *testing.T) {
	// Doc de Decrypt: solo escribe en dst los datos descifrados con éxito.
	// DARE.md, sección 3: nada se entrega antes de comprobar el tag. Si un
	// paquete está alterado, dst solo recibe los paquetes anteriores.
	for _, v := range versions {
		for _, tt := range authenticatedPrefixes {
			t.Run(v.name+"/"+tt.name, func(t *testing.T) {
				dst := bytes.NewBuffer([]byte{})
				_, _ = sio.Decrypt(dst, bytes.NewReader(tt.tamper(golden(v.name, maxPayloadSize+1))), v.config)
				assert.Equal(t, tt.want, dst.Bytes())
			})
		}
	}
}

func TestDecrypt_VersionOutsideRange(t *testing.T) {
	// Un flujo con una versión fuera del rango debe dar error.
	for _, tt := range versionsOutsideRange {
		t.Run(tt.name, func(t *testing.T) {
			config := sio.Config{Key: make([]byte, 32), MinVersion: tt.min, MaxVersion: tt.max}
			_, err := sio.Decrypt(io.Discard, bytes.NewReader(golden(tt.data, 1)), config)
			assert.Error(t, err)
		})
	}
}

func TestDecrypt_SourceError(t *testing.T) {
	// Mock de src que falla después de entregar parte del flujo cifrado.
	errSource := errors.New("source failed")
	prefixes := []struct {
		name string
		size int
	}{
		{"at start", 0},
		{"inside the first header", headerSize / 2},
		{"after one full package", maxPackageSize},
		{"inside the second package", maxPackageSize + headerSize + 1},
	}
	for _, v := range versions {
		for _, p := range prefixes {
			t.Run(v.name+"/"+p.name, func(t *testing.T) {
				stream := golden(v.name, maxPayloadSize+1)[:p.size]
				src := io.MultiReader(bytes.NewReader(stream), iotest.ErrReader(errSource))
				_, err := sio.Decrypt(io.Discard, src, v.config)
				assert.ErrorIs(t, err, errSource)
			})
		}
	}
}

func TestDecrypt_DestinationError(t *testing.T) {
	// Mock de dst que falla a partir de un byte del texto plano.
	errDestination := errors.New("destination failed")
	failures := []struct {
		name   string
		failAt int
	}{
		{"at start", 0},
		{"inside the first package", maxPayloadSize / 2},
		{"inside the second package", maxPayloadSize},
	}
	for _, v := range versions {
		for _, f := range failures {
			t.Run(v.name+"/"+f.name, func(t *testing.T) {
				dst := &failingWriter{failAt: f.failAt, err: errDestination}
				_, err := sio.Decrypt(dst, bytes.NewReader(golden(v.name, maxPayloadSize+1)), v.config)
				assert.ErrorIs(t, err, errDestination)
			})
		}
	}
}
