//go:build !race

package sio_test

import (
	"io"
	"testing"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"
)

// Pruebas no funcionales a nivel de integración (tipo JETM): EncryptWriter y
// DecryptReader trabajan juntos en un io.Pipe, como en TestIntegration_Pipe.
// Mismos requisitos que sio_performance_test.go (reports/performance.md), y
// tampoco se compila con -race.

// pipeRoundTrip cifra data con EncryptWriter en una goroutine y la descifra con
// DecryptReader desde el otro extremo de un io.Pipe.
func pipeRoundTrip(data []byte, config sio.Config) error {
	pr, pw := io.Pipe()
	go func() {
		w, err := sio.EncryptWriter(pw, config)
		if err == nil {
			_, err = w.Write(data)
		}
		if err == nil {
			err = w.Close()
		}
		_ = pw.CloseWithError(err)
	}()
	r, err := sio.DecryptReader(pr, config)
	if err == nil {
		_, err = io.Copy(io.Discard, r)
	}
	_ = pr.Close()
	return err
}

func TestIntegration_PipeAllocations(t *testing.T) {
	// RNF-3, definido a partir del README ("Support for long data streams - up
	// to 256 TB"): un flujo de 16 paquetes por el pipe no hace más reservas de
	// memoria que uno de 1.
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			small, large := testData(maxPayloadSize), testData(16*maxPayloadSize)
			allocsSmall := int(testing.AllocsPerRun(10, func() { _ = pipeRoundTrip(small, v.config) }))
			allocsLarge := int(testing.AllocsPerRun(10, func() { _ = pipeRoundTrip(large, v.config) }))
			assert.Equal(t, allocsSmall, allocsLarge)
		})
	}
}

func BenchmarkIntegration_PipeRoundTrip(b *testing.B) {
	// RNF-4: velocidad de cifrar y descifrar a la vez, con cada versión.
	for _, v := range versions {
		for _, s := range benchmarkSizes {
			b.Run(v.name+"/"+s.name, func(b *testing.B) {
				data := testData(s.size)
				b.SetBytes(int64(s.size))
				b.ReportAllocs()
				for b.Loop() {
					if err := pipeRoundTrip(data, v.config); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
