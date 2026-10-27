package sio_test

import (
	"bytes"
	"errors"
	"fmt"
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

// sparseReaderAt es un mock de io.ReaderAt para un flujo muy grande: solo tiene
// los bytes de data, colocados a partir del offset base. Antes no hay nada.
type sparseReaderAt struct {
	data []byte
	base int64
}

func (s sparseReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < s.base || off-s.base >= int64(len(s.data)) {
		return 0, io.EOF
	}
	n := copy(p, s.data[off-s.base:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// encryptW cifra src con EncryptWriter, escribiéndolo en trozos de chunk bytes
// (0: todo de una vez), y cierra el writer.
func encryptW(src []byte, config sio.Config, chunk int) ([]byte, error) {
	out := bytes.NewBuffer([]byte{}) // igual que io.ReadAll: vacío, no nil
	w, err := sio.EncryptWriter(out, config)
	if err != nil {
		return nil, err
	}
	err = writeAll(w, src, chunk)
	return out.Bytes(), err
}

// decryptW descifra src con DecryptWriter, escribiéndolo en trozos de chunk
// bytes (0: todo de una vez), y cierra el writer.
func decryptW(src []byte, config sio.Config, chunk int) ([]byte, error) {
	out := bytes.NewBuffer([]byte{}) // igual que io.ReadAll: vacío, no nil
	w, err := sio.DecryptWriter(out, config)
	if err != nil {
		return nil, err
	}
	err = writeAll(w, src, chunk)
	return out.Bytes(), err
}

// writeAll escribe src en w en trozos de chunk bytes (0: todo de una vez) y
// cierra w. Devuelve el primer error.
func writeAll(w io.WriteCloser, src []byte, chunk int) error {
	if chunk == 0 {
		chunk = max(len(src), 1)
	}
	for len(src) > 0 {
		n := min(chunk, len(src))
		if _, err := w.Write(src[:n]); err != nil {
			return err
		}
		src = src[n:]
	}
	return w.Close()
}

// failingWriter es un mock de io.Writer: acepta failAt bytes y falla con err
// en cualquier escritura que pase de ahí.
type failingWriter struct {
	written, failAt int
	err             error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.failAt {
		return 0, w.err
	}
	w.written += len(p)
	return len(p), nil
}

// catchPanic ejecuta f y devuelve su error. Si f hace panic, devuelve un error
// con el mensaje del panic, así la prueba falla con un assert y las demás
// pruebas siguen.
func catchPanic(f func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return f()
}
