package sio_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"
	"testing/iotest"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// EncryptReader

func TestEncryptReader_ValidConfig(t *testing.T) {
	for _, tt := range validConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.EncryptReader(bytes.NewReader(nil), tt.config)
			assert.NoError(t, err)
		})
	}
}

func TestEncryptReader_InvalidConfig(t *testing.T) {
	for _, tt := range invalidConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.EncryptReader(bytes.NewReader(nil), tt.config)
			assert.Error(t, err)
		})
	}
}

func TestEncryptReader_RandomKeySizes(t *testing.T) {
	// Datos aleatorios: solo las claves de 16 y 32 bytes son válidas.
	rapid.Check(t, func(t *rapid.T) {
		size := rapid.IntRange(0, 128).Draw(t, "key size")
		_, err := sio.EncryptReader(bytes.NewReader(nil), sio.Config{Key: make([]byte, size)})
		assert.Equal(t, size == 16 || size == 32, err == nil)
	})
}

func TestEncryptReader_FailingRand(t *testing.T) {
	// Sin Nonce, el nonce se lee de Config.Rand. Mocks de Rand que fallan o no
	// dan bytes suficientes deben producir un error.
	for _, v := range versions {
		for _, r := range failingRands {
			t.Run(v.name+"/"+r.name, func(t *testing.T) {
				config := v.config
				config.Nonce, config.Rand = nil, r.rand(v.randSize)
				_, err := sio.EncryptReader(bytes.NewReader(nil), config)
				assert.Error(t, err)
			})
		}
	}
}

func TestEncryptReader_Golden(t *testing.T) {
	// Con clave y nonce fijos, la salida es exactamente la de testdata/gen.py.
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				got, err := encrypt(bytes.NewReader(testData(s.size)), v.config, 0)
				assert.Equal(t, outcome[[]byte]{golden(v.name, s.size), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestEncryptReader_HeaderBytes(t *testing.T) {
	// DARE.md, sección 3: el byte 0 es la versión y el byte 1 el cifrado.
	for _, v := range versions {
		for _, c := range cipherSuites {
			t.Run(v.name+"/"+c.name, func(t *testing.T) {
				config := v.config
				config.CipherSuites = []byte{c.suite}
				out, err := encrypt(bytes.NewReader(testData(1)), config, 0)
				assert.Equal(t, outcome[[]byte]{[]byte{v.header, c.header}, nil}, outcome[[]byte]{out[:min(2, len(out))], err})
			})
		}
	}
}

func TestEncryptReader_VersionInRange(t *testing.T) {
	for _, tt := range versionRanges {
		t.Run(tt.name, func(t *testing.T) {
			config := sio.Config{Key: make([]byte, 32), MinVersion: tt.min, MaxVersion: tt.max}
			out, err := encrypt(bytes.NewReader(testData(1)), config, 0)
			assert.Equal(t, outcome[[]byte]{[]byte{tt.header}, nil}, outcome[[]byte]{out[:min(1, len(out))], err})
		})
	}
}

func TestEncryptReader_NoVersionInRange(t *testing.T) {
	// Ni la 1.0 ni la 2.0 están en el rango, así que cifrar debe dar error.
	for _, tt := range rangesWithoutVersion {
		t.Run(tt.name, func(t *testing.T) {
			config := sio.Config{Key: make([]byte, 32), MinVersion: tt.min, MaxVersion: tt.max}
			_, err := encrypt(bytes.NewReader(testData(1)), config, 0)
			assert.Error(t, err)
		})
	}
}

func TestEncryptReader_AnyReadSize(t *testing.T) {
	// La salida no depende del tamaño del buffer de lectura.
	// Fronteras: 1 byte, la cabecera, un paquete completo y ±1.
	bufSizes := []int{1, headerSize, maxPackageSize - 1, maxPackageSize, maxPackageSize + 1}
	for _, v := range versions {
		for _, size := range bufSizes {
			t.Run(fmt.Sprintf("%s/buffer %d", v.name, size), func(t *testing.T) {
				got, err := encrypt(bytes.NewReader(testData(maxPayloadSize+1)), v.config, size)
				assert.Equal(t, outcome[[]byte]{golden(v.name, maxPayloadSize+1), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestEncryptReader_WholeStreamBuffer(t *testing.T) {
	// Buffer de lectura de dos paquetes: todo el flujo cifrado cabe en él, con
	// cada tamaño del texto plano.
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				got, err := encrypt(bytes.NewReader(testData(s.size)), v.config, 2*maxPackageSize)
				assert.Equal(t, outcome[[]byte]{golden(v.name, s.size), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestEncryptReader_SlowSource(t *testing.T) {
	// Mocks de src que entregan los datos a trozos: la salida no cambia.
	sources := []struct {
		name string
		wrap func(io.Reader) io.Reader
	}{
		{"one byte per read", iotest.OneByteReader},
		{"half of each read", iotest.HalfReader},
		{"data and EOF together", iotest.DataErrReader},
	}
	for _, v := range versions {
		for _, s := range sources {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				got, err := encrypt(s.wrap(bytes.NewReader(testData(maxPayloadSize+1))), v.config, 0)
				assert.Equal(t, outcome[[]byte]{golden(v.name, maxPayloadSize+1), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestEncryptReader_SourceError(t *testing.T) {
	// Mock de src que falla después de entregar algunos bytes: el error
	// debe llegar al que lee. Buffer de lectura: menor y mayor que un paquete.
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
			for _, size := range []int{1, maxPackageSize} {
				t.Run(fmt.Sprintf("%s/%s/buffer %d", v.name, p.name, size), func(t *testing.T) {
					src := io.MultiReader(bytes.NewReader(testData(p.size)), iotest.ErrReader(errSource))
					_, err := encrypt(src, v.config, size)
					assert.ErrorIs(t, err, errSource)
				})
			}
		}
	}
}

func TestEncryptReader_ReadAfterEOF(t *testing.T) {
	// Unidad con estado: después de leer todo, doc de io.Reader: "The next
	// Read should return 0, EOF".
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				r, err := sio.EncryptReader(bytes.NewReader(testData(s.size)), v.config)
				if err == nil {
					_, err = io.ReadAll(r)
				}
				n := 0
				if err == nil {
					n, err = r.Read(make([]byte, 1))
				}
				assert.Equal(t, outcome[int]{0, io.EOF}, outcome[int]{n, err})
			})
		}
	}
}

// DecryptReader
//
// La entrada son las salidas de referencia de testdata y el resultado
// esperado es el texto plano conocido, testData(tamaño).

func TestDecryptReader_ValidConfig(t *testing.T) {
	for _, tt := range validConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.DecryptReader(bytes.NewReader(nil), tt.config)
			assert.NoError(t, err)
		})
	}
}

func TestDecryptReader_InvalidConfig(t *testing.T) {
	for _, tt := range invalidConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.DecryptReader(bytes.NewReader(nil), tt.config)
			assert.Error(t, err)
		})
	}
}

func TestDecryptReader_Golden(t *testing.T) {
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				got, err := decrypt(bytes.NewReader(golden(v.name, s.size)), v.config, 0)
				assert.Equal(t, outcome[[]byte]{testData(s.size), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestDecryptReader_DefaultConfig(t *testing.T) {
	// La configuración por defecto admite la 1.0 y la 2.0 (doc de Config), así
	// que descifra las salidas de referencia de las dos.
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				got, err := decrypt(bytes.NewReader(golden(v.name, s.size)), defaultConfig, 0)
				assert.Equal(t, outcome[[]byte]{testData(s.size), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestDecryptReader_AnyReadSize(t *testing.T) {
	// La salida no depende del tamaño del buffer de lectura.
	// Fronteras: 1 byte y un payload completo ±1.
	bufSizes := []int{1, maxPayloadSize - 1, maxPayloadSize, maxPayloadSize + 1}
	for _, v := range versions {
		for _, size := range bufSizes {
			t.Run(fmt.Sprintf("%s/buffer %d", v.name, size), func(t *testing.T) {
				got, err := decrypt(bytes.NewReader(golden(v.name, maxPayloadSize+1)), v.config, size)
				assert.Equal(t, outcome[[]byte]{testData(maxPayloadSize + 1), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestDecryptReader_Tampered(t *testing.T) {
	// Doc de DecryptReader: si el descifrado falla, el error es de tipo sio.Error.
	for _, v := range versions {
		for _, tt := range tamperings {
			t.Run(v.name+"/"+tt.name, func(t *testing.T) {
				stream := tt.tamper(golden(v.name, maxPayloadSize+1))
				_, err := decrypt(bytes.NewReader(stream), v.config, 0)
				assert.ErrorAs(t, err, new(sio.Error))
			})
		}
	}
}

func TestDecryptReader_DataAfterEnd(t *testing.T) {
	// Datos detrás del último paquete: en 1.0 su número de secuencia no es el
	// siguiente (DARE.md) y en 2.0 van detrás del paquete final (V2.md). Los
	// dos casos deben dar sio.Error.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			stream := append(golden(v.name, maxPayloadSize), golden(v.name, 1)...)
			_, err := decrypt(bytes.NewReader(stream), v.config, 0)
			assert.ErrorAs(t, err, new(sio.Error))
		})
	}
}

func TestDecryptReader_LastPackageRemoved(t *testing.T) {
	// V2.md: el último paquete lleva una marca de final, así que un flujo 2.0
	// sin él está incompleto. DARE 1.0 no tiene esa marca y DARE.md no promete
	// que lo detecte, así que solo se prueba la 2.0. Buffer: menor que un
	// paquete y de dos paquetes.
	stream := golden("2.0", maxPayloadSize+1)[:maxPackageSize]
	for _, size := range []int{1, 2 * maxPayloadSize} {
		t.Run(fmt.Sprintf("2.0/buffer %d", size), func(t *testing.T) {
			_, err := decrypt(bytes.NewReader(stream), onlyVersion20, size)
			assert.ErrorAs(t, err, new(sio.Error))
		})
	}
}

func TestDecryptReader_EmptyRead(t *testing.T) {
	// Doc de io.Reader: con len(p) == 0, Read puede devolver 0 y nil. Se prueba
	// como primera lectura, antes de saber la versión de los datos.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			r, err := sio.DecryptReader(bytes.NewReader(golden(v.name, 1)), defaultConfig)
			n := -1
			if err == nil {
				n, err = r.Read(nil)
			}
			assert.Equal(t, outcome[int]{0, nil}, outcome[int]{n, err})
		})
	}
}

func TestDecryptReader_WrongKey(t *testing.T) {
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			config := v.config
			config.Key = testData(32)
			_, err := decrypt(bytes.NewReader(golden(v.name, 1)), config, 0)
			assert.ErrorAs(t, err, new(sio.Error))
		})
	}
}

func TestDecryptReader_RandomTamperedByte(t *testing.T) {
	// Datos aleatorios: cambiar cualquier byte del flujo hace fallar el descifrado.
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.SampledFrom(versions).Draw(t, "version")
		stream := golden(v.name, maxPayloadSize+1)
		pos := rapid.IntRange(0, len(stream)-1).Draw(t, "position")
		stream[pos] ^= rapid.ByteRange(1, 255).Draw(t, "xor")
		_, err := decrypt(bytes.NewReader(stream), v.config, 0)
		assert.ErrorAs(t, err, new(sio.Error))
	})
}

func TestDecryptReader_VersionOutsideRange(t *testing.T) {
	// Un flujo con una versión fuera del rango debe dar error.
	for _, tt := range versionsOutsideRange {
		t.Run(tt.name, func(t *testing.T) {
			config := sio.Config{Key: make([]byte, 32), MinVersion: tt.min, MaxVersion: tt.max}
			_, err := decrypt(bytes.NewReader(golden(tt.data, 1)), config, 0)
			assert.Error(t, err)
		})
	}
}

func TestDecryptReader_SourceError(t *testing.T) {
	// Mock de src que falla después de entregar parte del flujo cifrado:
	// al principio, dentro de la cabecera, al completar un paquete y dentro
	// del segundo paquete.
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
				_, err := decrypt(src, v.config, 0)
				assert.ErrorIs(t, err, errSource)
			})
		}
	}
}

func TestDecryptReader_ReadAfterEOF(t *testing.T) {
	// Unidad con estado: después de leer todo, doc de io.Reader: "The next
	// Read should return 0, EOF".
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				r, err := sio.DecryptReader(bytes.NewReader(golden(v.name, s.size)), v.config)
				if err == nil {
					_, err = io.ReadAll(r)
				}
				n := 0
				if err == nil {
					n, err = r.Read(make([]byte, 1))
				}
				assert.Equal(t, outcome[int]{0, io.EOF}, outcome[int]{n, err})
			})
		}
	}
}

// DecryptReaderAt
//
// Igual que DecryptReader, pero lee el texto plano a partir de cualquier offset.

func TestDecryptReaderAt_ValidConfig(t *testing.T) {
	for _, tt := range validConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.DecryptReaderAt(bytes.NewReader(nil), tt.config)
			assert.NoError(t, err)
		})
	}
}

func TestDecryptReaderAt_InvalidConfig(t *testing.T) {
	for _, tt := range invalidConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sio.DecryptReaderAt(bytes.NewReader(nil), tt.config)
			assert.Error(t, err)
		})
	}
}

func TestDecryptReaderAt_Golden(t *testing.T) {
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				got, err := decryptAt(golden(v.name, s.size), v.config, 0, math.MaxInt)
				assert.Equal(t, outcome[[]byte]{testData(s.size), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestDecryptReaderAt_DefaultConfig(t *testing.T) {
	// La configuración por defecto admite la 1.0 y la 2.0 (doc de Config), así
	// que descifra las salidas de referencia de las dos.
	for _, v := range versions {
		for _, s := range plaintextSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				got, err := decryptAt(golden(v.name, s.size), defaultConfig, 0, math.MaxInt)
				assert.Equal(t, outcome[[]byte]{testData(s.size), nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestDecryptReaderAt_Ranges(t *testing.T) {
	// Fronteras alrededor del límite entre el primer paquete (64 KiB) y el
	// segundo (1 byte).
	ranges := []struct {
		name      string
		offset, n int
	}{
		{"first byte", 0, 1},
		{"from the second byte to the end", 1, maxPayloadSize},
		{"last byte of the first package", maxPayloadSize - 1, 1},
		{"across the package boundary", maxPayloadSize - 1, 2},
		{"first byte of the second package", maxPayloadSize, 1},
	}
	plaintext := testData(maxPayloadSize + 1)
	for _, v := range versions {
		for _, r := range ranges {
			t.Run(v.name+"/"+r.name, func(t *testing.T) {
				got, err := decryptAt(golden(v.name, maxPayloadSize+1), v.config, r.offset, r.n)
				want := plaintext[r.offset : r.offset+r.n]
				assert.Equal(t, outcome[[]byte]{want, nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestDecryptReaderAt_RandomRange(t *testing.T) {
	// Datos aleatorios: cualquier trozo del texto plano se lee correctamente.
	plaintext := testData(maxPayloadSize + 1)
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.SampledFrom(versions).Draw(t, "version")
		offset := rapid.IntRange(0, len(plaintext)).Draw(t, "offset")
		n := rapid.IntRange(0, len(plaintext)-offset).Draw(t, "n")
		got, err := decryptAt(golden(v.name, len(plaintext)), v.config, offset, n)
		assert.Equal(t, outcome[[]byte]{plaintext[offset : offset+n], nil}, outcome[[]byte]{got, err})
	})
}

func TestDecryptReaderAt_SingleCall(t *testing.T) {
	// Doc de io.ReaderAt: ReadAt lee len(p) bytes, y si lee menos devuelve un
	// error. Un solo ReadAt de un paquete completo, sin llegar al final del
	// flujo, con cada versión y con la configuración por defecto.
	plaintext := testData(maxPayloadSize + 1)
	for _, v := range versions {
		for _, c := range []struct {
			name   string
			config sio.Config
		}{{"version config", v.config}, {"default config", defaultConfig}} {
			t.Run(v.name+"/"+c.name, func(t *testing.T) {
				r, err := sio.DecryptReaderAt(bytes.NewReader(golden(v.name, maxPayloadSize+1)), c.config)
				p := make([]byte, maxPayloadSize)
				n := 0
				if err == nil {
					n, err = r.ReadAt(p, 0)
				}
				assert.Equal(t, outcome[[]byte]{plaintext[:maxPayloadSize], nil}, outcome[[]byte]{p[:n], err})
			})
		}
	}
}

func TestDecryptReaderAt_PastEnd(t *testing.T) {
	// Doc de io.EOF: es el error que indica que no hay más datos. io.ReadAll lo
	// trata como fin sin error, así que se esperan los bytes que quedan y nil.
	// Cada paquete ocupa 64 KiB de offsets, así que hay dos fronteras: el final
	// de los datos y el final del último paquete.
	reads := []struct {
		name            string
		size, offset, n int // tamaño del texto plano, offset y bytes pedidos
		want            []byte
	}{
		{"at the end", maxPayloadSize + 1, maxPayloadSize + 1, 1, []byte{}},
		{"across the end", maxPayloadSize + 1, maxPayloadSize, 2, testData(maxPayloadSize + 1)[maxPayloadSize:]},
		{"at the end of the last package", maxPayloadSize + 1, 2 * maxPayloadSize, 1, []byte{}},
		{"one byte past the last package", maxPayloadSize + 1, 2*maxPayloadSize + 1, 1, []byte{}},
		{"full package, one byte past the end", maxPayloadSize, maxPayloadSize + 1, 1, []byte{}},
	}
	for _, v := range versions {
		for _, r := range reads {
			t.Run(v.name+"/"+r.name, func(t *testing.T) {
				got, err := decryptAt(golden(v.name, r.size), v.config, r.offset, r.n)
				assert.Equal(t, outcome[[]byte]{r.want, nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestDecryptReaderAt_LastPackages(t *testing.T) {
	// DARE.md: el número de secuencia es un uint32, así que un flujo tiene hasta
	// 2^32 paquetes y el último tiene el número 2^32-1. Un flujo tan grande no
	// cabe en memoria: se cifra un solo paquete de 2 bytes con ese número de
	// secuencia, un mock de io.ReaderAt lo pone en su offset del flujo y se lee
	// su segundo byte. (Con DARE 2.0, una lectura en el primer byte de un
	// paquete empieza en el paquete anterior, que el mock no tiene.)
	packages := []struct {
		name string
		seq  uint32
	}{
		{"one before the last package", math.MaxUint32 - 1},
		{"last package", math.MaxUint32},
	}
	plaintext := testData(2)
	for _, v := range versions {
		for _, p := range packages {
			t.Run(v.name+"/"+p.name, func(t *testing.T) {
				config := v.config
				config.SequenceNumber = p.seq
				stream := &bytes.Buffer{}
				if _, err := sio.Encrypt(stream, bytes.NewReader(plaintext), config); err != nil {
					t.Fatal(err)
				}
				src := sparseReaderAt{stream.Bytes(), int64(p.seq) * maxPackageSize}
				r, err := sio.DecryptReaderAt(src, v.config)
				got := make([]byte, 1)
				if err == nil {
					_, err = r.ReadAt(got, int64(p.seq)*maxPayloadSize+1)
				}
				assert.Equal(t, outcome[[]byte]{plaintext[1:], nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestDecryptReaderAt_BeyondMaximumSize(t *testing.T) {
	// DARE.md: un flujo tiene como mucho 2^32 paquetes. Un offset en el paquete
	// 2^32 está fuera de cualquier flujo válido, así que ReadAt debe dar error
	// aunque src tenga allí un paquete correcto (con número de secuencia 0,
	// que es 2^32 en un uint32).
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			stream := &bytes.Buffer{}
			if _, err := sio.Encrypt(stream, bytes.NewReader(testData(2)), v.config); err != nil {
				t.Fatal(err)
			}
			src := sparseReaderAt{stream.Bytes(), maxPackages * maxPackageSize}
			r, err := sio.DecryptReaderAt(src, v.config)
			if err == nil {
				_, err = r.ReadAt(make([]byte, 1), maxPackages*maxPayloadSize+1)
			}
			assert.Error(t, err)
		})
	}
}

func TestDecryptReaderAt_NegativeOffset(t *testing.T) {
	offsets := []int64{-1, math.MinInt64}
	for _, v := range versions {
		for _, offset := range offsets {
			t.Run(fmt.Sprintf("%s/offset %d", v.name, offset), func(t *testing.T) {
				r, err := sio.DecryptReaderAt(bytes.NewReader(golden(v.name, 1)), v.config)
				if err == nil {
					_, err = r.ReadAt(make([]byte, 1), offset)
				}
				assert.Error(t, err)
			})
		}
	}
}

func TestDecryptReaderAt_Tampered(t *testing.T) {
	// Doc de DecryptReaderAt: si el descifrado falla, el error es de tipo sio.Error.
	for _, v := range versions {
		for _, tt := range tamperings {
			t.Run(v.name+"/"+tt.name, func(t *testing.T) {
				stream := tt.tamper(golden(v.name, maxPayloadSize+1))
				_, err := decryptAt(stream, v.config, 0, maxPayloadSize+1)
				assert.ErrorAs(t, err, new(sio.Error))
			})
		}
	}
}

func TestDecryptReaderAt_UnknownVersion(t *testing.T) {
	// Con la configuración por defecto, DecryptReaderAt detecta la versión en el
	// primer byte. Un byte que no es 1.0 ni 2.0 debe dar sio.Error.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			stream := golden(v.name, 1)
			stream[0] = 0x30
			_, err := decryptAt(stream, defaultConfig, 0, 1)
			assert.ErrorAs(t, err, new(sio.Error))
		})
	}
}

func TestDecryptReaderAt_EmptyRead(t *testing.T) {
	// Doc de io.ReaderAt: con len(p) == 0 no hay nada que leer. Se prueba como
	// primera lectura, antes de saber la versión de los datos.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			r, err := sio.DecryptReaderAt(bytes.NewReader(golden(v.name, 1)), defaultConfig)
			n := -1
			if err == nil {
				n, err = r.ReadAt(nil, 0)
			}
			assert.Equal(t, outcome[int]{0, nil}, outcome[int]{n, err})
		})
	}
}

func TestDecryptReaderAt_VersionOutsideRange(t *testing.T) {
	// Un flujo con una versión fuera del rango debe dar error.
	for _, tt := range versionsOutsideRange {
		t.Run(tt.name, func(t *testing.T) {
			config := sio.Config{Key: make([]byte, 32), MinVersion: tt.min, MaxVersion: tt.max}
			_, err := decryptAt(golden(tt.data, 1), config, 0, 1)
			assert.Error(t, err)
		})
	}
}

func TestDecryptReaderAt_SourceError(t *testing.T) {
	// Mock de src que falla a partir de un byte del flujo cifrado: al
	// principio, dentro de la cabecera y dentro del segundo paquete.
	errSource := errors.New("source failed")
	failures := []struct {
		name   string
		failAt int
	}{
		{"at start", 0},
		{"inside the first header", headerSize / 2},
		{"inside the second package", maxPackageSize + headerSize + 1},
	}
	for _, v := range versions {
		for _, f := range failures {
			t.Run(v.name+"/"+f.name, func(t *testing.T) {
				src := failingReaderAt{golden(v.name, maxPayloadSize+1), f.failAt, errSource}
				r, err := sio.DecryptReaderAt(src, v.config)
				if err == nil {
					_, err = io.ReadAll(io.NewSectionReader(r, 0, maxPayloadSize+1))
				}
				assert.ErrorIs(t, err, errSource)
			})
		}
	}
}

func TestDecryptReaderAt_ReadOrder(t *testing.T) {
	// Doc de io.ReaderAt: cada lectura indica su offset, así que el resultado
	// no depende de las lecturas anteriores. Se lee un trozo, luego otro y
	// luego el primero otra vez: debe salir lo mismo.
	orders := []struct {
		name          string
		first, second int // offsets de las dos primeras lecturas
	}{
		{"first package, then second package", 0, maxPayloadSize},
		{"second package, then first package", maxPayloadSize, 0},
		{"same offset twice", maxPayloadSize - 1, maxPayloadSize - 1},
	}
	plaintext := testData(maxPayloadSize + 1)
	for _, v := range versions {
		for _, o := range orders {
			t.Run(v.name+"/"+o.name, func(t *testing.T) {
				r, err := sio.DecryptReaderAt(bytes.NewReader(golden(v.name, maxPayloadSize+1)), v.config)
				var got []byte
				if err == nil {
					// Las dos primeras lecturas también deben ir bien: sus
					// errores se juntan con el de la tercera.
					_, err1 := io.ReadAll(io.NewSectionReader(r, int64(o.first), 2))
					_, err2 := io.ReadAll(io.NewSectionReader(r, int64(o.second), 2))
					got, err = io.ReadAll(io.NewSectionReader(r, int64(o.first), 2))
					err = errors.Join(err1, err2, err)
				}
				want := plaintext[o.first:min(o.first+2, len(plaintext))]
				assert.Equal(t, outcome[[]byte]{want, nil}, outcome[[]byte]{got, err})
			})
		}
	}
}
