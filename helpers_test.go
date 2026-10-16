package sio_test

import (
	"bytes"
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

// decrypt descifra src con DecryptReader y lee toda la salida con un buffer de
// bufSize bytes (0: io.ReadAll).
func decrypt(src io.Reader, config sio.Config, bufSize int) ([]byte, error) {
	r, err := sio.DecryptReader(src, config)
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

// decryptAt descifra src con DecryptReaderAt y lee n bytes de texto plano a
// partir de offset. io.SectionReader convierte el io.ReaderAt en un io.Reader.
func decryptAt(src []byte, config sio.Config, offset, n int) ([]byte, error) {
	r, err := sio.DecryptReaderAt(bytes.NewReader(src), config)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.NewSectionReader(r, int64(offset), int64(n)))
}

// failingReaderAt es un mock de io.ReaderAt: entrega data hasta el byte failAt
// y falla con err en cualquier lectura que pase de ahí.
type failingReaderAt struct {
	data   []byte
	failAt int
	err    error
}

func (f failingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if int(off)+len(p) > f.failAt {
		return 0, f.err
	}
	return copy(p, f.data[off:]), nil
}
