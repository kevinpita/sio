package sio_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
			for _, c := range writeChunks {
				t.Run(v.name+"/"+f.name+"/"+c.name, func(t *testing.T) {
					w, err := sio.EncryptWriter(&failingWriter{failAt: f.failAt, err: errDestination}, v.config)
					if err == nil {
						err = writeAll(w, testData(maxPayloadSize+1), c.chunk)
					}
					assert.ErrorIs(t, err, errDestination)
				})
			}
		}
	}
}

func TestEncryptWriter_WriteAfterError(t *testing.T) {
	// Unidad con estado: después de un Write que falla porque dst falla, el
	// flujo cifrado ya está roto, así que el siguiente Write también falla.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			w, err := sio.EncryptWriter(&failingWriter{err: errors.New("destination failed")}, v.config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(testData(maxPayloadSize + 1)); err == nil {
				t.Fatal("first Write did not fail")
			}
			_, err = w.Write(testData(1))
			assert.Error(t, err)
		})
	}
}

func TestEncryptWriter_CloseAfterError(t *testing.T) {
	// Doc de EncryptWriter: Close termina el cifrado. Si un Write ya falló, el
	// cifrado no puede terminar bien, así que Close devuelve error.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			w, err := sio.EncryptWriter(&failingWriter{err: errors.New("destination failed")}, v.config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(testData(maxPayloadSize + 1)); err == nil {
				t.Fatal("first Write did not fail")
			}
			assert.Error(t, w.Close())
		})
	}
}

func TestEncryptWriter_ClosableDestinationError(t *testing.T) {
	// dst también es un io.Closer: un io.PipeWriter cuyo lector está cerrado.
	// El último paquete se escribe en Close y falla. Doc de EncryptWriter: Close
	// debe ir bien para terminar el cifrado, así que Close devuelve ese error
	// aunque cerrar dst vaya bien.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			_ = pr.Close()
			w, err := sio.EncryptWriter(pw, v.config)
			if err == nil {
				err = writeAll(w, testData(1), 0)
			}
			assert.ErrorIs(t, err, io.ErrClosedPipe)
		})
	}
}

func TestEncryptWriter_EmptyWrite(t *testing.T) {
	// Doc de io.Writer: Write de 0 bytes escribe 0 bytes.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			w, err := sio.EncryptWriter(&bytes.Buffer{}, v.config)
			n := -1
			if err == nil {
				n, err = w.Write(nil)
			}
			assert.Equal(t, outcome[int]{0, nil}, outcome[int]{n, err})
		})
	}
}

func TestEncryptWriter_WriteAfterClose(t *testing.T) {
	// Unidad con estado. Doc de EncryptWriter: Close termina el proceso, así que
	// después ya no se puede escribir en el flujo. Se espera que Close vaya
	// bien (error nil) y que el Write posterior falle (true). Close dos veces
	// no se prueba: doc de io.Closer, "the behavior of Close after the first
	// call is undefined".
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			w, err := sio.EncryptWriter(&bytes.Buffer{}, v.config)
			writeFailed := false
			if err == nil {
				err = writeAll(w, testData(1), 0)
			}
			if err == nil {
				_, writeErr := w.Write(testData(1))
				writeFailed = writeErr != nil
			}
			assert.Equal(t, outcome[bool]{true, nil}, outcome[bool]{writeFailed, err})
		})
	}
}

// DecryptWriter
//
// La entrada son las salidas de referencia de testdata y el resultado
// esperado es el texto plano conocido, testData(tamaño).

func TestDecryptWriter_ValidConfig(t *testing.T) {
	for _, tt := range validConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.DecryptWriter(&bytes.Buffer{}, tt.config)
			assert.NoError(t, err)
		})
	}
}

func TestDecryptWriter_InvalidConfig(t *testing.T) {
	for _, tt := range invalidConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.DecryptWriter(&bytes.Buffer{}, tt.config)
			assert.Error(t, err)
		})
	}
}

func TestDecryptWriter_Golden(t *testing.T) {
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				got, err := decryptW(golden(v.name, s.size), v.config, 0)
				assert.Equal(t, outcome[[]byte]{testData(s.size), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestDecryptWriter_DefaultConfig(t *testing.T) {
	// La configuración por defecto admite la 1.0 y la 2.0 (doc de Config), así
	// que descifra las salidas de referencia de las dos, en uno o en varios Write.
	for _, v := range versions {
		for _, s := range plaintextSizes {
			for _, c := range writeChunks {
				t.Run(v.name+"/"+s.name+"/"+c.name, func(t *testing.T) {
					got, err := decryptW(golden(v.name, s.size), defaultConfig, c.chunk)
					assert.Equal(t, outcome[[]byte]{testData(s.size), nil}, outcome[[]byte]{got, err})
				})
			}
		}
	}
}

func TestDecryptWriter_SmallPackagesSplitWrites(t *testing.T) {
	// DARE 1.0 con PayloadSize 1: dos paquetes de 33 bytes. El primer Write
	// corta la primera cabecera (15 bytes) y el segundo lleva el resto, que
	// pasa por el final del primer paquete.
	config := onlyVersion10
	config.PayloadSize = 1
	stream := &bytes.Buffer{}
	if _, err := sio.Encrypt(stream, bytes.NewReader(testData(2)), config); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	w, err := sio.DecryptWriter(out, config)
	if err == nil {
		_, err = w.Write(stream.Bytes()[:15])
	}
	if err == nil {
		_, err = w.Write(stream.Bytes()[15:])
	}
	if err == nil {
		err = w.Close()
	}
	assert.Equal(t, outcome[[]byte]{testData(2), nil}, outcome[[]byte]{out.Bytes(), err})
}

func TestDecryptWriter_AnyWriteSize(t *testing.T) {
	// La salida no depende del tamaño de cada Write.
	// Fronteras: 1 byte, la cabecera y un paquete completo ±1.
	writeSizes := []int{1, headerSize, maxPackageSize - 1, maxPackageSize, maxPackageSize + 1}
	for _, v := range versions {
		for _, size := range writeSizes {
			t.Run(fmt.Sprintf("%s/write %d", v.name, size), func(t *testing.T) {
				got, err := decryptW(golden(v.name, maxPayloadSize+1), v.config, size)
				assert.Equal(t, outcome[[]byte]{testData(maxPayloadSize + 1), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestDecryptWriter_RandomWriteSizes(t *testing.T) {
	// Datos aleatorios: escribir el flujo cifrado en trozos de tamaño
	// aleatorio da el mismo texto plano.
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.SampledFrom(versions).Draw(t, "version")
		out := &bytes.Buffer{}
		w, err := sio.DecryptWriter(out, v.config)
		for src := golden(v.name, maxPayloadSize+1); err == nil && len(src) > 0; {
			n := rapid.IntRange(1, len(src)).Draw(t, "write size")
			_, err = w.Write(src[:n])
			src = src[n:]
		}
		if err == nil {
			err = w.Close()
		}
		assert.Equal(t, outcome[[]byte]{testData(maxPayloadSize + 1), nil}, outcome[[]byte]{out.Bytes(), err})
	})
}

func TestDecryptWriter_Tampered(t *testing.T) {
	// Doc de DecryptWriter: si el descifrado falla, el error es de tipo sio.Error.
	for _, v := range versions {
		for _, tt := range tamperings {
			for _, c := range writeChunks {
				t.Run(v.name+"/"+tt.name+"/"+c.name, func(t *testing.T) {
					stream := tt.tamper(golden(v.name, maxPayloadSize+1))
					_, err := decryptW(stream, v.config, c.chunk)
					assert.ErrorAs(t, err, new(sio.Error))
				})
			}
		}
	}
}

func TestDecryptWriter_UnknownVersion(t *testing.T) {
	// Con la configuración por defecto, DecryptWriter detecta la versión en el
	// primer byte. Un byte que no es 1.0 ni 2.0 debe dar sio.Error.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			stream := golden(v.name, 1)
			stream[0] = 0x30
			_, err := decryptW(stream, defaultConfig, 0)
			assert.ErrorAs(t, err, new(sio.Error))
		})
	}
}

func TestDecryptWriter_ClosableDestinationError(t *testing.T) {
	// Igual que en EncryptWriter: dst es un io.PipeWriter cuyo lector está
	// cerrado. Doc de DecryptWriter: Close debe ir bien para terminar el
	// descifrado, así que el error de la escritura llega al que escribe, en
	// Write o en Close, aunque cerrar dst vaya bien.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			_ = pr.Close()
			w, err := sio.DecryptWriter(pw, v.config)
			if err == nil {
				err = writeAll(w, golden(v.name, 1), 0)
			}
			assert.ErrorIs(t, err, io.ErrClosedPipe)
		})
	}
}

func TestDecryptWriter_EmptyWrite(t *testing.T) {
	// Doc de io.Writer: Write de 0 bytes escribe 0 bytes. Se prueba como primer
	// Write, antes de saber la versión de los datos.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			w, err := sio.DecryptWriter(&bytes.Buffer{}, defaultConfig)
			n := -1
			if err == nil {
				n, err = w.Write(nil)
			}
			assert.Equal(t, outcome[int]{0, nil}, outcome[int]{n, err})
		})
	}
}

func TestDecryptWriter_OnlyAuthenticatedOutput(t *testing.T) {
	// DARE.md, sección 3: el texto plano nunca se entrega antes de comprobar
	// el tag. Si un paquete está alterado, dst solo recibe los paquetes
	// anteriores, que sí se han comprobado.
	for _, v := range versions {
		for _, tt := range authenticatedPrefixes {
			t.Run(v.name+"/"+tt.name, func(t *testing.T) {
				got, _ := decryptW(tt.tamper(golden(v.name, maxPayloadSize+1)), v.config, 0)
				assert.Equal(t, tt.want, got)
			})
		}
	}
}

func TestDecryptWriter_VersionOutsideRange(t *testing.T) {
	// Un flujo con una versión fuera del rango debe dar error.
	for _, tt := range versionsOutsideRange {
		t.Run(tt.name, func(t *testing.T) {
			config := sio.Config{Key: make([]byte, 32), MinVersion: tt.min, MaxVersion: tt.max}
			_, err := decryptW(golden(tt.data, 1), config, 0)
			assert.Error(t, err)
		})
	}
}

func TestDecryptWriter_DestinationError(t *testing.T) {
	// Mock de dst que falla a partir de un byte del texto plano: el error
	// debe llegar al que escribe, en Write o en Close.
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
			for _, c := range writeChunks {
				t.Run(v.name+"/"+f.name+"/"+c.name, func(t *testing.T) {
					w, err := sio.DecryptWriter(&failingWriter{failAt: f.failAt, err: errDestination}, v.config)
					if err == nil {
						err = writeAll(w, golden(v.name, maxPayloadSize+1), c.chunk)
					}
					assert.ErrorIs(t, err, errDestination)
				})
			}
		}
	}
}

func TestDecryptWriter_WriteAfterError(t *testing.T) {
	// Unidad con estado: después de un Write que falla porque dst falla, el
	// siguiente Write también falla.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			w, err := sio.DecryptWriter(&failingWriter{err: errors.New("destination failed")}, v.config)
			if err != nil {
				t.Fatal(err)
			}
			stream := golden(v.name, maxPayloadSize+1)
			if _, err := w.Write(stream[:maxPackageSize]); err == nil {
				t.Fatal("first Write did not fail")
			}
			_, err = w.Write(stream[maxPackageSize:])
			assert.Error(t, err)
		})
	}
}

func TestDecryptWriter_CloseAfterError(t *testing.T) {
	// Doc de DecryptWriter: Close termina el descifrado. Si un Write ya falló,
	// el descifrado no puede terminar bien, así que Close devuelve error.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			w, err := sio.DecryptWriter(&failingWriter{err: errors.New("destination failed")}, v.config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(golden(v.name, maxPayloadSize+1)); err == nil {
				t.Fatal("first Write did not fail")
			}
			assert.Error(t, w.Close())
		})
	}
}

func TestDecryptWriter_WriteAfterClose(t *testing.T) {
	// Unidad con estado. Doc de DecryptWriter: Close termina el proceso, así que
	// después ya no se puede escribir en el flujo. Se espera que Close vaya
	// bien (error nil) y que el Write posterior falle (true). Close dos veces
	// no se prueba: doc de io.Closer, "the behavior of Close after the first
	// call is undefined".
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			w, err := sio.DecryptWriter(&bytes.Buffer{}, v.config)
			writeFailed := false
			if err == nil {
				err = writeAll(w, golden(v.name, 1), 0)
			}
			if err == nil {
				_, writeErr := w.Write(golden(v.name, 1))
				writeFailed = writeErr != nil
			}
			assert.Equal(t, outcome[bool]{true, nil}, outcome[bool]{writeFailed, err})
		})
	}
}
