package sio_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"
)

// Pruebas de integración: sio con la biblioteca estándar de Go (io.Pipe,
// io.CopyBuffer, os.File) y con goroutines. Se buscan errores de sincronía:
// datos que se pierden o se desordenan cuando cada lado va a su ritmo.

func TestIntegration_Pipe(t *testing.T) {
	// Una goroutine cifra con EncryptWriter dentro de un io.Pipe y otra lee
	// del otro extremo con DecryptReader. Doc de io.Pipe: cada Write espera
	// a que el otro lado lea, así que los dos lados van sincronizados. Al
	// acabar de leer se cierra el lector, para que el escritor no se quede
	// esperando si el descifrado falla antes de tiempo. Se escribe en trozos
	// de 1000 bytes, que no coinciden con los paquetes de 64 KiB.
	for _, v := range versions {
		for _, s := range roundTripSizes {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				pr, pw := io.Pipe()
				writeErr := make(chan error, 1)
				go func() {
					w, err := sio.EncryptWriter(pw, v.config)
					if err == nil {
						err = writeAll(w, testData(s.size), 1000)
					}
					writeErr <- err
					_ = pw.CloseWithError(err)
				}()
				got, err := decrypt(pr, v.config, 0)
				_ = pr.Close()
				assert.Equal(t, outcome[[]byte]{testData(s.size), nil}, outcome[[]byte]{got, errors.Join(<-writeErr, err)})
			})
		}
	}
}

func TestIntegration_ChainedReaders(t *testing.T) {
	// DecryptReader lee directamente de EncryptReader, que lee de un origen
	// que entrega los datos a trozos (mocks de testing/iotest).
	sources := []struct {
		name string
		wrap func(io.Reader) io.Reader
	}{
		{"all at once", func(r io.Reader) io.Reader { return r }},
		{"one byte per read", iotest.OneByteReader},
		{"half of each read", iotest.HalfReader},
	}
	plaintext := testData(2*maxPayloadSize + 1)
	for _, v := range versions {
		for _, s := range sources {
			t.Run(v.name+"/"+s.name, func(t *testing.T) {
				var got []byte
				encrypted, err := sio.EncryptReader(s.wrap(bytes.NewReader(plaintext)), v.config)
				if err == nil {
					got, err = decrypt(encrypted, v.config, 0)
				}
				assert.Equal(t, outcome[[]byte]{plaintext, nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestIntegration_CopyReaderToWriter(t *testing.T) {
	// io.CopyBuffer lleva los datos de EncryptReader a DecryptWriter. El
	// tamaño del buffer de la copia cambia cómo se trocean los datos.
	// Fronteras: 1 byte y un paquete cifrado completo ±1.
	bufSizes := []int{1, maxPackageSize - 1, maxPackageSize, maxPackageSize + 1}
	plaintext := testData(2*maxPayloadSize + 1)
	for _, v := range versions {
		for _, size := range bufSizes {
			t.Run(fmt.Sprintf("%s/buffer %d", v.name, size), func(t *testing.T) {
				dst := bytes.NewBuffer([]byte{})
				encrypted, err := sio.EncryptReader(bytes.NewReader(plaintext), v.config)
				var decrypting io.WriteCloser
				if err == nil {
					decrypting, err = sio.DecryptWriter(dst, v.config)
				}
				if err == nil {
					_, err = io.CopyBuffer(decrypting, encrypted, make([]byte, size))
				}
				if err == nil {
					err = decrypting.Close()
				}
				assert.Equal(t, outcome[[]byte]{plaintext, nil}, outcome[[]byte]{dst.Bytes(), err})
			})
		}
	}
}

func TestIntegration_FileReaderAt(t *testing.T) {
	// Se cifra a un fichero con Encrypt y se lee con DecryptReaderAt sobre el
	// os.File, que es un io.ReaderAt. Fronteras alrededor de los paquetes.
	ranges := []struct {
		name      string
		offset, n int
	}{
		{"whole stream", 0, 2*maxPayloadSize + 1},
		{"last byte of the first package", maxPayloadSize - 1, 1},
		{"across the first package boundary", maxPayloadSize - 1, 2},
		{"whole middle package", maxPayloadSize, maxPayloadSize},
		{"last byte of the stream", 2 * maxPayloadSize, 1},
	}
	plaintext := testData(2*maxPayloadSize + 1)
	for _, v := range versions {
		file := encryptToFile(t, plaintext, v.config)
		for _, r := range ranges {
			t.Run(v.name+"/"+r.name, func(t *testing.T) {
				var got []byte
				decrypting, err := sio.DecryptReaderAt(file, v.config)
				if err == nil {
					got, err = io.ReadAll(io.NewSectionReader(decrypting, int64(r.offset), int64(r.n)))
				}
				assert.Equal(t, outcome[[]byte]{plaintext[r.offset : r.offset+r.n], nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

func TestIntegration_ParallelReadAt(t *testing.T) {
	// Doc de io.ReaderAt: "Clients of ReadAt can execute parallel ReadAt
	// calls on the same input source". Varias goroutines leen a la vez trozos
	// del mismo os.File. Trozos que coinciden con los paquetes y que no.
	tests := []struct {
		name  string
		chunk int // bytes que lee cada goroutine
	}{
		{"one package per goroutine", maxPayloadSize},
		{"chunks across packages", maxPayloadSize/2 + 1},
		{"small chunks", 1000},
	}
	plaintext := testData(4*maxPayloadSize + 1)
	for _, v := range versions {
		file := encryptToFile(t, plaintext, v.config)
		for _, tt := range tests {
			t.Run(v.name+"/"+tt.name, func(t *testing.T) {
				var got []byte
				decrypting, err := sio.DecryptReaderAt(file, v.config)
				if err == nil {
					got, err = readAtInParallel(decrypting, len(plaintext), tt.chunk)
				}
				assert.Equal(t, outcome[[]byte]{plaintext, nil}, outcome[[]byte]{got, err})
			})
		}
	}
}

// encryptToFile cifra plaintext con Encrypt en un fichero temporal y lo
// devuelve abierto. El fichero se cierra y se borra al acabar la prueba.
func encryptToFile(t *testing.T, plaintext []byte, config sio.Config) *os.File {
	t.Helper()
	file, err := os.Create(filepath.Join(t.TempDir(), "stream.dare"))
	if err == nil {
		t.Cleanup(func() { _ = file.Close() })
		_, err = sio.Encrypt(file, bytes.NewReader(plaintext), config)
	}
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// readAtInParallel lee r en trozos de chunk bytes, cada trozo en su propia
// goroutine y todas a la vez, y junta los trozos en orden.
func readAtInParallel(r io.ReaderAt, size, chunk int) ([]byte, error) {
	count := (size + chunk - 1) / chunk
	parts := make([][]byte, count)
	errs := make([]error, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			offset := i * chunk
			parts[i], errs[i] = io.ReadAll(io.NewSectionReader(r, int64(offset), int64(min(chunk, size-offset))))
		}()
	}
	wg.Wait()
	return bytes.Join(parts, nil), errors.Join(errs...)
}
