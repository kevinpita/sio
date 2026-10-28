//go:build !race

package sio_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"
)

// Pruebas no funcionales a nivel de unidad (tipo JETM). Cada prueba comprueba
// un requisito de reports/performance.md, sacado del README de sio. El
// detector de carreras (-race) cambia el tiempo y las reservas de memoria, así
// que este fichero no se compila con -race.

func TestPerformance_SizeOverhead(t *testing.T) {
	// RNF-1. README: "encryption increases the amount of data by ~0.05%". Se
	// comprueba con flujos de paquetes completos, de 1 MiB a 256 TiB.
	sizes := []struct {
		name string
		size uint64
	}{
		{"1 MiB", 1 << 20},
		{"1 GiB", 1 << 30},
		{"maximum size", maxPlaintextSize},
	}
	for _, s := range sizes {
		t.Run(s.name, func(t *testing.T) {
			encrypted, err := sio.EncryptedSize(s.size)
			overhead := float64(encrypted-s.size) / float64(s.size)
			assert.Equal(t, outcome[bool]{true, nil}, outcome[bool]{overhead <= 0.0005, err})
		})
	}
}

func TestPerformance_RandomAccess(t *testing.T) {
	// RNF-2. README: "Random access - arbitrary sequences / ranges can be
	// decrypted independently". Leer 1 byte del último paquete con
	// DecryptReaderAt lee como mucho un paquete cifrado, sea cual sea el tamaño
	// del flujo.
	for _, v := range versions {
		for _, packages := range []int{4, 64} {
			t.Run(fmt.Sprintf("%s/%d packages", v.name, packages), func(t *testing.T) {
				stream := &bytes.Buffer{}
				if _, err := sio.Encrypt(stream, bytes.NewReader(testData(packages*maxPayloadSize)), v.config); err != nil {
					t.Fatal(err)
				}
				src := &countingReaderAt{r: bytes.NewReader(stream.Bytes())}
				r, err := sio.DecryptReaderAt(src, v.config)
				if err == nil {
					_, err = r.ReadAt(make([]byte, 1), int64(packages-1)*maxPayloadSize+1)
				}
				assert.Equal(t, outcome[bool]{true, nil}, outcome[bool]{src.read <= maxPackageSize, err})
			})
		}
	}
}

func TestPerformance_Allocations(t *testing.T) {
	// RNF-3, definido a partir del README ("Support for long data streams - up
	// to 256 TB"): cifrar o descifrar un flujo más largo no hace más reservas de
	// memoria. Con 16 paquetes, las mismas que con 1. Si no, un flujo de 2^32
	// paquetes haría miles de millones de reservas.
	for _, v := range versions {
		small, large := testData(maxPayloadSize), testData(16*maxPayloadSize)
		smallStream, largeStream := &bytes.Buffer{}, &bytes.Buffer{}
		if _, err := sio.Encrypt(smallStream, bytes.NewReader(small), v.config); err != nil {
			t.Fatal(err)
		}
		if _, err := sio.Encrypt(largeStream, bytes.NewReader(large), v.config); err != nil {
			t.Fatal(err)
		}
		tests := []struct {
			name         string
			small, large func()
		}{
			{"Encrypt",
				func() { _, _ = sio.Encrypt(io.Discard, bytes.NewReader(small), v.config) },
				func() { _, _ = sio.Encrypt(io.Discard, bytes.NewReader(large), v.config) }},
			{"Decrypt",
				func() { _, _ = sio.Decrypt(io.Discard, bytes.NewReader(smallStream.Bytes()), v.config) },
				func() { _, _ = sio.Decrypt(io.Discard, bytes.NewReader(largeStream.Bytes()), v.config) }},
		}
		for _, tt := range tests {
			t.Run(v.name+"/"+tt.name, func(t *testing.T) {
				assert.Equal(t, int(testing.AllocsPerRun(10, tt.small)), int(testing.AllocsPerRun(10, tt.large)))
			})
		}
	}
}

// RNF-4. README, tabla "Performance": velocidad de cifrado y descifrado con
// cada cifrado y tamaño. Depende de la máquina, así que no tiene assert: el
// resultado se compara con la tabla en reports/performance.md.
var benchmarkSizes = []struct {
	name string
	size int
}{
	{"8 KB", 8 << 10},
	{"64 KB", 64 << 10},
	{"512 KB", 512 << 10},
	{"1 MB", 1 << 20},
}

func BenchmarkEncrypt(b *testing.B) {
	for _, c := range cipherSuites {
		for _, s := range benchmarkSizes {
			b.Run(c.name+"/"+s.name, func(b *testing.B) {
				config := sio.Config{Key: make([]byte, 32), CipherSuites: []byte{c.suite}}
				data := testData(s.size)
				b.SetBytes(int64(s.size))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := sio.Encrypt(io.Discard, bytes.NewReader(data), config); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for _, c := range cipherSuites {
		for _, s := range benchmarkSizes {
			b.Run(c.name+"/"+s.name, func(b *testing.B) {
				config := sio.Config{Key: make([]byte, 32), CipherSuites: []byte{c.suite}}
				stream := &bytes.Buffer{}
				if _, err := sio.Encrypt(stream, bytes.NewReader(testData(s.size)), config); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(s.size))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := sio.Decrypt(io.Discard, bytes.NewReader(stream.Bytes()), config); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
