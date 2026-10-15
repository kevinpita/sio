package sio_test

import (
	"errors"
	"io"

	"github.com/minio/sio"
)

// outcome junta valor y error para comprobarlos con una sola aserción compuesta.
type outcome[T any] struct {
	Value T
	Err   error
}

// encrypt cifra src con EncryptReader y lee toda la salida con un buffer de
// bufSize bytes (0: io.ReadAll).
func encrypt(src io.Reader, config sio.Config, bufSize int) ([]byte, error) {
	r, err := sio.EncryptReader(src, config)
	if err != nil {
		return nil, err
	}
	return readAll(r, bufSize)
}

// readAll lee r hasta io.EOF usando siempre un buffer de bufSize bytes.
func readAll(r io.Reader, bufSize int) ([]byte, error) {
	if bufSize == 0 {
		return io.ReadAll(r)
	}
	out := []byte{} // igual que io.ReadAll: vacío, no nil
	buf := make([]byte, bufSize)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}
