package main_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Pruebas de sistema: se compila ncrypt y se ejecuta como lo haría un usuario,
// siguiendo la doc del paquete (main.go). La contraseña se pasa con -p. Un
// error termina con un código de salida distinto de 0.

const phrase = "contraseña de prueba"

// Cifrados que muestra "ncrypt -list" y que acepta -cipher.
var ciphers = []string{"AES256", "C20P1305"}

// testData devuelve n bytes con la secuencia 0, 1, ..., 250, 0, 1, ...
func testData(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i % 251)
	}
	return data
}

// Tamaños del texto plano: vacío, 1 byte y más de un paquete de 64 KiB.
var sizes = []struct {
	name string
	size int
}{
	{"empty", 0},
	{"one byte", 1},
	{"more than one package", 64*1024 + 1},
}

func TestNcrypt_FileRoundTrip(t *testing.T) {
	// Ejemplo de la doc: "ncrypt in out" cifra un fichero en otro. Se
	// descifra con "ncrypt -d in out".
	for _, s := range sizes {
		t.Run(s.name, func(t *testing.T) {
			dir := t.TempDir()
			plain, enc, dec := filepath.Join(dir, "plain"), filepath.Join(dir, "enc"), filepath.Join(dir, "dec")
			err := os.WriteFile(plain, testData(s.size), 0o600)
			if err == nil {
				_, err = ncrypt(nil, "-p", phrase, plain, enc)
			}
			if err == nil {
				_, err = ncrypt(nil, "-d", "-p", phrase, enc, dec)
			}
			var got []byte
			if err == nil {
				got, err = os.ReadFile(dec) //nolint:gosec // fichero de t.TempDir
			}
			assert.Equal(t, outcome[[]byte]{testData(s.size), nil}, outcome[[]byte]{got, err})
		})
	}
}

func TestNcrypt_FileToStdout(t *testing.T) {
	// Ejemplo de la doc: "ncrypt -d in" descifra un fichero y escribe el
	// contenido en la salida estándar.
	for _, s := range sizes {
		t.Run(s.name, func(t *testing.T) {
			enc := filepath.Join(t.TempDir(), "enc")
			encrypted, err := ncrypt(testData(s.size), "-p", phrase)
			if err == nil {
				err = os.WriteFile(enc, encrypted, 0o600)
			}
			var got []byte
			if err == nil {
				got, err = ncrypt(nil, "-d", "-p", phrase, enc)
			}
			assert.Equal(t, outcome[[]byte]{testData(s.size), nil}, outcome[[]byte]{got, err})
		})
	}
}

func TestNcrypt_StdinStdoutRoundTrip(t *testing.T) {
	// Doc: sin fichero de entrada lee de la entrada estándar y escribe en la
	// salida estándar.
	for _, s := range sizes {
		t.Run(s.name, func(t *testing.T) {
			var got []byte
			encrypted, err := ncrypt(testData(s.size), "-p", phrase)
			if err == nil {
				got, err = ncrypt(encrypted, "-d", "-p", phrase)
			}
			assert.Equal(t, outcome[[]byte]{testData(s.size), nil}, outcome[[]byte]{got, err})
		})
	}
}

func TestNcrypt_List(t *testing.T) {
	// Doc: -list muestra los cifrados admitidos.
	for _, name := range ciphers {
		t.Run(name, func(t *testing.T) {
			list, err := ncrypt(nil, "-list")
			assert.Equal(t, outcome[bool]{true, nil}, outcome[bool]{bytes.Contains(list, []byte(name)), err})
		})
	}
}

func TestNcrypt_CipherRoundTrip(t *testing.T) {
	// Doc: -cipher elige el cifrado. Con cada uno se cifra y se descifra.
	for _, name := range ciphers {
		t.Run(name, func(t *testing.T) {
			var got []byte
			encrypted, err := ncrypt(testData(1000), "-cipher", name, "-p", phrase)
			if err == nil {
				got, err = ncrypt(encrypted, "-d", "-p", phrase)
			}
			assert.Equal(t, outcome[[]byte]{testData(1000), nil}, outcome[[]byte]{got, err})
		})
	}
}

func TestNcrypt_Errors(t *testing.T) {
	// Entradas que el programa no puede procesar: debe terminar con un código
	// de salida distinto de 0.
	encrypted, err := ncrypt(testData(1000), "-p", phrase)
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	if err == nil {
		err = os.WriteFile(plain, testData(1000), 0o600)
	}
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(encrypted)
	tampered[len(tampered)-1] ^= 1
	tests := []struct {
		name  string
		stdin []byte
		args  []string
	}{
		{"wrong password", encrypted, []string{"-d", "-p", "otra contraseña"}},
		{"tampered data", tampered, []string{"-d", "-p", phrase}},
		{"truncated data", encrypted[:10], []string{"-d", "-p", phrase}},
		{"unknown cipher", testData(1000), []string{"-cipher", "DES", "-p", phrase}},
		{"input file does not exist", nil, []string{"-p", phrase, filepath.Join(dir, "missing")}},
		{"input file does not exist, with output file", nil, []string{"-p", phrase, filepath.Join(dir, "missing"), filepath.Join(dir, "out")}},
		{"output directory does not exist", nil, []string{"-p", phrase, plain, filepath.Join(dir, "missing", "out")}},
		{"input is a directory", nil, []string{"-p", phrase, dir}},
		{"input is a directory, with output file", nil, []string{"-p", phrase, dir, filepath.Join(dir, "out")}},
		{"too many arguments", nil, []string{"-p", phrase, plain, filepath.Join(dir, "out"), filepath.Join(dir, "extra")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ncrypt(tt.stdin, tt.args...)
			assert.ErrorAs(t, err, new(*exec.ExitError))
		})
	}
}

func TestNcrypt_Help(t *testing.T) {
	// Doc del paquete flag: -h muestra la ayuda. ncrypt termina con código 0.
	_, err := ncrypt(nil, "-h")
	assert.NoError(t, err)
}

// outcome junta valor y error para comprobarlos con una sola aserción.
type outcome[T any] struct {
	Value T
	Err   error
}

// binary es la ruta del ncrypt compilado por TestMain.
var binary string

// TestMain compila ncrypt una vez, ejecuta las pruebas y borra el binario. Con
// GOCOVERDIR, el binario se compila con -cover y guarda allí su cobertura.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ncrypt")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binary = filepath.Join(dir, "ncrypt")
	args := []string{"build", "-o", binary}
	if os.Getenv("GOCOVERDIR") != "" {
		args = append(args, "-cover")
	}
	code := 1
	if out, err := exec.Command("go", append(args, ".")...).CombinedOutput(); err != nil { //nolint:gosec // ruta de os.MkdirTemp
		fmt.Fprintln(os.Stderr, string(out), err)
	} else {
		code = m.Run()
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// ncrypt ejecuta el programa con stdin y args, y devuelve su salida estándar.
// Si el programa termina con un código distinto de 0, el error es un
// *exec.ExitError junto con lo que escribió en la salida de error.
func ncrypt(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(binary, args...) //nolint:gosec // el binario compilado por TestMain
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		err = errors.Join(err, errors.New(stderr.String()))
	}
	return stdout.Bytes(), err
}
