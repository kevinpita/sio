package sio_test

import (
	"bytes"
	"fmt"
	"go/build"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"
)

// Pruebas estructurales de caja blanca (tipo ArchUnit).

func TestArchitecture_AllowedDependencies(t *testing.T) {
	// El paquete sio solo importa la biblioteca estándar, golang.org/x/crypto y
	// golang.org/x/sys.
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range pkg.Imports {
		t.Run(path, func(t *testing.T) {
			imported, findErr := build.Import(path, ".", build.FindOnly)
			standard := findErr == nil && imported.Goroot
			allowed := standard ||
				strings.HasPrefix(path, "golang.org/x/crypto/") ||
				strings.HasPrefix(path, "golang.org/x/sys/")
			assert.True(t, allowed)
		})
	}
}

func TestArchitecture_VersionDispatch(t *testing.T) {
	// Cada constructor público elige la implementación interna según la Config.
	// Por defecto, al cifrar usa la versión 2.0 y al descifrar una que detecta
	// la versión. %T da el nombre del tipo devuelto.
	encReader := func(c sio.Config) (any, error) { return sio.EncryptReader(strings.NewReader(""), c) }
	encWriter := func(c sio.Config) (any, error) { return sio.EncryptWriter(io.Discard, c) }
	decReader := func(c sio.Config) (any, error) { return sio.DecryptReader(strings.NewReader(""), c) }
	decReaderAt := func(c sio.Config) (any, error) { return sio.DecryptReaderAt(strings.NewReader(""), c) }
	decWriter := func(c sio.Config) (any, error) { return sio.DecryptWriter(io.Discard, c) }
	tests := []struct {
		name      string
		construct func(sio.Config) (any, error)
		config    sio.Config
		want      string
	}{
		{"EncryptReader/only 1.0", encReader, onlyVersion10, "*sio.encReaderV10"},
		{"EncryptReader/only 2.0", encReader, onlyVersion20, "*sio.encReaderV20"},
		{"EncryptReader/default", encReader, defaultConfig, "*sio.encReaderV20"},
		{"EncryptWriter/only 1.0", encWriter, onlyVersion10, "*sio.encWriterV10"},
		{"EncryptWriter/only 2.0", encWriter, onlyVersion20, "*sio.encWriterV20"},
		{"EncryptWriter/default", encWriter, defaultConfig, "*sio.encWriterV20"},
		{"DecryptReader/only 1.0", decReader, onlyVersion10, "*sio.decReaderV10"},
		{"DecryptReader/only 2.0", decReader, onlyVersion20, "*sio.decReaderV20"},
		{"DecryptReader/default", decReader, defaultConfig, "*sio.decReader"},
		{"DecryptReaderAt/only 1.0", decReaderAt, onlyVersion10, "*sio.decReaderAtV10"},
		{"DecryptReaderAt/only 2.0", decReaderAt, onlyVersion20, "*sio.decReaderAtV20"},
		{"DecryptReaderAt/default", decReaderAt, defaultConfig, "*sio.decReaderAt"},
		{"DecryptWriter/only 1.0", decWriter, onlyVersion10, "*sio.decWriterV10"},
		{"DecryptWriter/only 2.0", decWriter, onlyVersion20, "*sio.decWriterV20"},
		{"DecryptWriter/default", decWriter, defaultConfig, "*sio.decWriter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.construct(tt.config)
			assert.Equal(t, outcome[string]{tt.want, nil}, outcome[string]{fmt.Sprintf("%T", got), err})
		})
	}
}

func TestArchitecture_VersionDetection(t *testing.T) {
	// Con la configuración por defecto, el lector o escritor genérico mira la
	// versión del primer paquete y guarda dentro (campo src o dst) la
	// implementación de esa versión.
	read := func(s []byte) (any, error) {
		r, err := sio.DecryptReader(bytes.NewReader(s), defaultConfig)
		if err == nil {
			_, err = r.Read(make([]byte, 1))
		}
		return r, err
	}
	readAt := func(s []byte) (any, error) {
		r, err := sio.DecryptReaderAt(bytes.NewReader(s), defaultConfig)
		if err == nil {
			_, err = r.ReadAt(make([]byte, 1), 0)
		}
		return r, err
	}
	write := func(s []byte) (any, error) {
		w, err := sio.DecryptWriter(io.Discard, defaultConfig)
		if err == nil {
			_, err = w.Write(s)
		}
		return w, err
	}
	tests := []struct {
		name    string
		use     func([]byte) (any, error)
		version string
		field   string
		want    string
	}{
		{"DecryptReader/1.0 stream", read, "1.0", "src", "*sio.decReaderV10"},
		{"DecryptReader/2.0 stream", read, "2.0", "src", "*sio.decReaderV20"},
		{"DecryptReaderAt/1.0 stream", readAt, "1.0", "src", "*sio.decReaderAtV10"},
		{"DecryptReaderAt/2.0 stream", readAt, "2.0", "src", "*sio.decReaderAtV20"},
		{"DecryptWriter/1.0 stream", write, "1.0", "dst", "*sio.decWriterV10"},
		{"DecryptWriter/2.0 stream", write, "2.0", "dst", "*sio.decWriterV20"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generic, err := tt.use(golden(tt.version, 1))
			var got string
			if err == nil {
				got = storedType(generic, tt.field)
			}
			assert.Equal(t, outcome[string]{tt.want, nil}, outcome[string]{got, err})
		})
	}
}

// storedType da el tipo guardado en el campo privado field de v. Si el campo no
// existe o está vacío, devuelve un texto que hace fallar el assert.
func storedType(v any, field string) string {
	f := reflect.ValueOf(v).Elem().FieldByName(field)
	if !f.IsValid() || f.IsNil() {
		return "no value in field " + field
	}
	return f.Elem().Type().String()
}
