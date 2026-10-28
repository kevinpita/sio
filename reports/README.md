# Informe de pruebas de `sio`

Proyecto de Verificación e Validación de Software. El software probado es [`github.com/minio/sio`](https://github.com/minio/sio): una biblioteca de Go que cifra flujos de datos con el formato DARE ([`DARE.md`](../DARE.md)), más el programa `cmd/ncrypt`, que la usa desde la línea de comandos.

Este informe es el último paso del ciclo de pruebas: resume qué se probó, con qué técnica y qué se encontró. Cada sección enlaza a su evidencia.

## Resumen

| | |
|---|---|
| Casos de prueba | 1311 (subtests), en 13 ficheros |
| Casos que fallan a propósito | 78, todos por bugs con issue ([`known-failures.txt`](known-failures.txt)) |
| Cobertura de sentencias | 93,6 % de la biblioteca, 77,5 % de `ncrypt` |
| Cobertura de condiciones | 510 de 570 (89 %) |
| Mutantes muertos | 396 de 446 (88,8 %) |
| Issues | 13: 10 bugs, 2 mejoras y 1 error de documentación |

## Herramientas

Go no usa las herramientas de Java de la asignatura. Esta tabla da la equivalente de cada una.

| Técnica (rúbrica) | Java | Go | Tipo |
|---|---|---|---|
| Unidad e integración | JUnit | paquete `testing`, [testify](https://github.com/stretchr/testify) (`assert`) y [rapid](https://pkg.go.dev/pgregory.net/rapid) (datos aleatorios) | Dinámica, caja negra, funcional |
| Estática funcional | SpotBugs | `go vet`, `staticcheck`, `gosec` (con `golangci-lint`) | Estática, caja blanca, funcional |
| Estática no funcional | CheckStyle | `gofmt`, `revive`, `gocritic`, `gocyclo`, `gocognit`, `misspell` (con `golangci-lint`) | Estática, caja blanca, no funcional |
| Estructural | ArchUnit | `go/build` (imports) y comprobaciones del tipo devuelto (`%T`, `reflect`) | Estática (imports) y dinámica (composición), caja blanca, estructural |
| No funcional | JETM | `testing.B` (benchmarks), `testing.AllocsPerRun`, `benchstat` | Dinámica, caja blanca, no funcional |
| Cobertura | JaCoCo | `go test -cover`, [`gobco`](https://github.com/rillig/gobco) (condiciones) | Métrica |
| Mutación | PIT | [`gremlins`](https://gremlins.dev/) | Métrica |

El entorno está en [`devenv.nix`](../devenv.nix): `devenv shell` instala todas las herramientas con versión fija.

## Resultados por técnica

### 1. Pruebas de unidad

**Ficheros:** un fichero por familia de funciones públicas, en la raíz del paquete (en Go, las pruebas van junto al código).

| Fichero | Unidad |
|---|---|
| [`sio_size_test.go`](../sio_size_test.go) | `EncryptedSize`, `DecryptedSize` |
| [`sio_reader_test.go`](../sio_reader_test.go) | `EncryptReader`, `DecryptReader`, `DecryptReaderAt` |
| [`sio_writer_test.go`](../sio_writer_test.go) | `EncryptWriter`, `DecryptWriter` |
| [`sio_encrypt_test.go`](../sio_encrypt_test.go) | `Encrypt`, `Decrypt`, `DecryptBuffer` |
| [`sio_error_test.go`](../sio_error_test.go) | el tipo `Error` |

Datos compartidos: [`fixtures_test.go`](../fixtures_test.go) (particiones y valores frontera), [`spec_test.go`](../spec_test.go) (constantes de `DARE.md`) y [`helpers_test.go`](../helpers_test.go) (mocks).

- **Por qué un fichero por familia y no por función:** las diapositivas definen la unidad como un conjunto de operaciones públicas y como una unidad con estado. Un `io.Reader` es una unidad con estado (cada `Read` depende de los anteriores), y los tres lectores comparten particiones, golden files y mocks.
- **Caja negra:** las pruebas están en el paquete `sio_test` y solo usan la API pública.
- **Valor esperado independiente:** sale de `DARE.md`, de los comentarios de la API, de la documentación de `io` o de golden files. Los golden files ([`testdata/`](../testdata)) los genera [`testdata/gen.py`](../testdata/gen.py) en Python a partir de la especificación, sin usar `sio`. `DARE.md` solo describe la versión 1.0, así que la 2.0 se describe en [`testdata/V2.md`](../testdata/V2.md), reconstruida a partir de los comentarios del código.
- **Selección de datos:** particiones de equivalencia (configuraciones válidas y no válidas, tamaños), valores frontera (0 bytes, 1 byte, un paquete de 64 KiB y ±1, 2^32 paquetes) y datos aleatorios con `rapid`.
- **Mocks:** lectores y escritores que fallan en un byte dado (`failingReaderAt`, `failingWriter`), lectores de `testing/iotest` y un `io.ReaderAt` para flujos de 256 TiB que no caben en memoria (`sparseReaderAt`).
- **Un assert por prueba:** cada `t.Run` tiene un solo `assert`. Cuando una función devuelve un valor y un error, los dos se comparan juntos con `outcome[T]{valor, error}`. `t.Fatal` solo se usa en la preparación.

### 2. Análisis estático funcional

[`static-functional.md`](static-functional.md). `gosec` marcó una conversión `uint32(t)` en `ReadAt`. Al revisarla apareció un error de límite (el último paquete de un flujo máximo no se puede leer): prueba `TestDecryptReaderAt_LastPackages` e issue **#9**. El resto de hallazgos están clasificados como falsos positivos, con el motivo.

### 3. Análisis estático no funcional

[`static-nonfunctional.md`](static-nonfunctional.md). Hallazgos con issue: complejidad muy alta de las funciones `Read` de DARE 2.0 (**#10**) y la documentación de `Config.Key` (**#11**), que confirma una prueba nueva con clave de 128 bits y ChaCha20. Los demás (nombres en mayúsculas, `Config` por valor, orden de campos) se aceptan con su motivo, porque cambiarlos rompe la API pública.

### 4. Pruebas de integración funcionales

| Fichero | Componentes que cooperan |
|---|---|
| [`sio_roundtrip_integration_test.go`](../sio_roundtrip_integration_test.go) | cada función de cifrado con cada función de descifrado |
| [`sio_config_integration_test.go`](../sio_config_integration_test.go) | versiones, cifrados, claves y números de secuencia distintos al cifrar y al descifrar |
| [`sio_size_integration_test.go`](../sio_size_integration_test.go) | `EncryptedSize`/`DecryptedSize` con los bytes que producen `Encrypt` y `Decrypt` |
| [`sio_pipeline_integration_test.go`](../sio_pipeline_integration_test.go) | `io.Pipe`, lectores encadenados, `io.Copy`, ficheros y `ReadAt` en paralelo |
| [`cmd/ncrypt/ncrypt_integration_test.go`](../cmd/ncrypt/ncrypt_integration_test.go) | el programa `ncrypt` con la biblioteca, a nivel de sistema |

- En estas pruebas, el valor esperado puede ser la salida real del otro componente: por ejemplo, el número de bytes que devuelve `Encrypt` para comprobar `EncryptedSize`.
- `ncrypt` se prueba compilando el binario y ejecutándolo. No se puede llamar a `main()` dentro de la prueba, porque el programa termina con `os.Exit`. La contraseña interactiva no se prueba, porque necesita un terminal.

### 5. Pruebas estructurales

[`sio_architecture_integration_test.go`](../sio_architecture_integration_test.go). Tres aspectos:

- **Dependencias** (estática, no ejecuta `sio`): la biblioteca solo importa la biblioteca estándar, `golang.org/x/crypto` y `golang.org/x/sys`.
- **Composición** (dinámica): cada constructor público devuelve la implementación interna que corresponde a la `Config` (DARE 1.0, 2.0 o la que detecta la versión).
- **Detección de versión** (dinámica): el lector o escritor genérico guarda dentro la implementación de la versión del flujo.

Las dos últimas dependen de nombres internos (tipos y campos privados): si el código cambia esos nombres, hay que cambiar las pruebas.

### 6. Pruebas no funcionales

[`performance.md`](performance.md). Requisitos sacados del README de `sio`: sobrecoste de tamaño de ~0,05 %, acceso aleatorio y velocidad, más uno definido por nosotros (las reservas de memoria no crecen con el tamaño del flujo). Pruebas con assert y benchmarks a nivel de unidad ([`sio_performance_test.go`](../sio_performance_test.go)) y de integración ([`sio_performance_integration_test.go`](../sio_performance_integration_test.go)). DARE 2.0 reserva memoria en cada paquete (**#13**). La velocidad medida es mayor que la tabla del README.

### 7. Cobertura

[`coverage.md`](coverage.md). No se llega al 100 %. Cada línea y cada condición sin cubrir está justificada: código muerto, ramas que dependen del procesador, errores que la validación previa hace imposibles y comportamiento no documentado. Las líneas que sí se podían alcanzar desde la API pública tienen ahora una prueba.

### 8. Mutación

[`mutation.md`](mutation.md). De 64 mutantes vivos se pasó a 50 con 7 pruebas nuevas o ampliadas. Los 50 que quedan están analizados uno a uno: 45 son equivalentes, 4 cambian un resultado que la documentación no especifica y 1 solo cambia el resultado de un bug abierto. El análisis de ese último llevó a un bug nuevo (**#12**: `DecryptBuffer` hace panic).

## Discrepancias encontradas

Cada issue tiene un solo objetivo y enlaza el commit de la prueba, la prueba y la técnica que la encontró.

| Issue | Tipo | Técnica | Discrepancia |
|---|---|---|---|
| [#1](https://github.com/kevinpita/sio/issues/1) | bug | Unidad | Todas las funciones que reciben una `Config` aceptan `PayloadSize` negativo |
| [#2](https://github.com/kevinpita/sio/issues/2) | bug | Unidad e integración | El descifrado no acepta un flujo DARE 2.0 vacío creado por `EncryptReader` |
| [#3](https://github.com/kevinpita/sio/issues/3) | bug | Unidad | Las funciones de descifrado aceptan datos con una versión fuera de `MinVersion` y `MaxVersion` |
| [#4](https://github.com/kevinpita/sio/issues/4) | bug | Unidad | `DecryptReaderAt` (DARE 2.0) da "unexpected EOF" con offsets más allá del último paquete |
| [#5](https://github.com/kevinpita/sio/issues/5) | bug | Unidad | `EncryptReader`, `EncryptWriter` y `Encrypt` cifran con una versión fuera del rango |
| [#6](https://github.com/kevinpita/sio/issues/6) | bug | Unidad | `DecryptBuffer` no descifra un flujo vacío con la configuración por defecto |
| [#7](https://github.com/kevinpita/sio/issues/7) | bug | Unidad (estado) | `EncryptWriter` (DARE 1.0) acepta `Write` después de `Close` |
| [#8](https://github.com/kevinpita/sio/issues/8) | bug | Integración | `EncryptedSize` y `DecryptedSize` no tienen en cuenta `PayloadSize` (DARE 1.0) |
| [#9](https://github.com/kevinpita/sio/issues/9) | bug | Estática funcional | `DecryptReaderAt` no lee el último paquete de un flujo de tamaño máximo |
| [#10](https://github.com/kevinpita/sio/issues/10) | mejora | Estática no funcional | Complejidad muy alta en las funciones `Read` de DARE 2.0 |
| [#11](https://github.com/kevinpita/sio/issues/11) | documentación | Estática no funcional | La doc de `Config.Key` dice 32 bytes, pero se aceptan 16 |
| [#12](https://github.com/kevinpita/sio/issues/12) | bug | Mutación | `DecryptBuffer` hace panic con un flujo DARE 2.0 cortado |
| [#13](https://github.com/kevinpita/sio/issues/13) | mejora | No funcional | DARE 2.0 reserva memoria en cada paquete |

**10 bugs** en una biblioteca de unas 2000 líneas. Casi todos están en la validación de la `Config` y en los casos límite de DARE 2.0.

## Pruebas que fallan

Las pruebas de los bugs **fallan a propósito**: no se saltan con `t.Skip`, para que el fallo se vea. Hoy fallan 78 casos. [`known-failures.txt`](known-failures.txt) los lista agrupados por issue. Cuando se arregle un bug, hay que borrar su grupo de la lista.

La lista la usa la mutación ([`mutation.sh`](mutation.sh)), que necesita que todo lo demás pase. Para ejecutar solo lo que debe pasar:

```sh
go test -skip "$(grep '^Test' reports/known-failures.txt | python3 -c '
import re, sys
e = lambda s: "^" + re.escape(s) + "$"
print("|".join("/".join(map(e, t.strip().split("/"))) for t in sys.stdin))')" ./...
```

El CI de `.github/workflows/go.yml` es el del proyecto original y no se ejecuta en este fork.

## Cómo reproducirlo

```sh
devenv shell                       # instala Go y las herramientas
go test ./...                      # todas las pruebas (78 casos fallan a propósito)
go test -race ./...                # lo mismo con el detector de carreras (sin las pruebas de rendimiento)
golangci-lint run ./...            # análisis estático con la configuración del repositorio
python3 testdata/gen.py            # vuelve a generar los golden files
vvs-bench                          # benchmarks (reports/bench.txt)
vvs-mutate                         # mutación (reports/mutation.txt)
```

Los comandos de cada análisis están en su informe.

## Limitaciones

- **No probado:** `Close` dos veces (la doc de `io.Closer` dice que el resultado no está definido), leer después de un error y la contraseña interactiva de `ncrypt`.
- **DARE 2.0 no tiene especificación.** Los golden files de 2.0 siguen [`testdata/V2.md`](../testdata/V2.md), que se escribió a partir del código. Si el código tiene un error que también está en esa nota, las pruebas no lo ven.
- **Rendimiento:** la velocidad depende de la máquina, así que no tiene assert. La comparación con el README es aproximada (otra máquina y otra versión de Go).
- **Pruebas estructurales:** dependen de nombres internos de tipos y campos.
