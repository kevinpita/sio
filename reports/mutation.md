# Pruebas de mutación

Fila 8 de la rúbrica. La herramienta es [`gremlins`](https://gremlins.dev/) v0.6.0, sobre el paquete `sio` (la biblioteca), con sus operadores por defecto: `ARITHMETIC_BASE` (`+` por `-`...), `CONDITIONALS_BOUNDARY` (`<` por `<=`...), `CONDITIONALS_NEGATION` (`==` por `!=`...), `INCREMENT_DECREMENT` y `INVERT_NEGATIVES`.

## Cómo se ejecuta

```sh
vvs-mutate   # ejecuta reports/mutation.sh y guarda la salida en reports/mutation.txt
```

`reports/mutation.sh` hace 3 cosas antes de llamar a `gremlins`:

1. **Salta los subtests que fallan por bugs abiertos** con `go test -skip`. Si no, `gremlins` vería un fallo con cualquier mutante y lo daría por muerto. La lista está en [`known-failures.txt`](known-failures.txt), agrupada por issue (#1 a #9 y #12). Solo salta esos subtests, no la prueba entera. Antes de empezar, el script comprueba que todas las demás pruebas pasan: si hay un fallo que no está en la lista, para.
2. **Copia los ficheros del repositorio a un directorio temporal.** `gremlins` no puede copiar el directorio `.devenv` y se para con `panic: error, this is temporary`.
3. **Usa `-count=1`.** `gremlins` calcula el tiempo límite de cada mutante con el tiempo de las pruebas. Con la caché de `go test`, ese tiempo es casi 0 y todos los mutantes acaban en "timed out".

No se usa la opción `--test-cpu`: en v0.6.0 pasa `"-cpu 2"` como un solo argumento a `go test`, que falla siempre, y todos los mutantes salen como muertos.

## Resultado

| | Antes | Después |
|---|---|---|
| Mutantes muertos (killed) | 380 | 396 |
| Mutantes vivos (lived) | 64 | 50 |
| Tiempo agotado (timed out) | 20 | 19 |
| No cubiertos | 27 | 26 |
| Eficacia (`killed / (killed + lived)`) | 85,6 % | 88,8 % |

Salidas completas: [`mutation-before.txt`](mutation-before.txt) y [`mutation.txt`](mutation.txt).

- **Eficacia:** `gremlins` no cuenta los de tiempo agotado.
- **Tiempo agotado:** las pruebas no terminan en el tiempo límite. Normalmente el mutante hace que una función no termine nunca. Por ejemplo, `r.stateErr != nil` -> `==` hace que `Read` devuelva `0, nil` siempre, e `io.ReadAll` no acaba. Las pruebas notan el mutante, porque no terminan, pero no con un assert.
- **No cubiertos:** están en las líneas que ninguna prueba ejecuta. Están justificadas en [`coverage.md`](coverage.md).
- **Vivos:** de los 50 que quedan, 45 son equivalentes, 4 cambian el resultado pero ninguna documentación dice cuál debe ser, y 1 solo cambia el resultado de un bug abierto (issue #12). La justificación está abajo.

## Pruebas nuevas

Cada prueba mata mutantes que antes vivían. Se comprobó a mano aplicando el mutante: por ejemplo, con `t+1` -> `t-1` en `reader-v2.go:302`, `TestDecryptReaderAt_BeyondMaximumSize/2.0` falla.

| Mutantes que mata | Prueba | Qué faltaba |
|---|---|---|
| `reader-v1.go:221` y `reader-v2.go:302` (6): `t+1 > (1<<32)-1` | `TestDecryptReaderAt_BeyondMaximumSize` | Ninguna prueba leía más allá del tamaño máximo de un flujo (2^32 paquetes). Con el mutante, el número de paquete 2^32 pasa a 0 en un `uint32` y `ReadAt` devuelve datos |
| `reader-v2.go:114` (1): `n + ... + 1 + nn` | `TestEncryptReader_WholeStreamBuffer` | Ninguna prueba leía con un buffer donde cabe todo el flujo. Con el mutante, `Read` devuelve un número de bytes incorrecto |
| `reader-v2.go:77` (1): `err != nil` | `TestIntegration_RandomRoundTrip`, ahora con el primer byte aleatorio | `testData` siempre empieza por 0. Con el mutante se pierde el primer byte y se cifra un 0 en su lugar, y eso no se notaba. Es una prueba aleatoria: con 100 casos, la probabilidad de que el primer byte sea siempre 0 es despreciable |
| `generic.go:173,178` (2): `err != nil` | `TestDecryptReaderAt_SingleCall` | Las pruebas leían con `io.ReadAll`, que repite la lectura. Con el mutante, el primer `ReadAt` devuelve `0, nil`, y la doc de `io.ReaderAt` lo prohíbe |
| `writer-v1.go:56` (2): `headerSize - w.offset` | `TestDecryptWriter_SmallPackagesSplitWrites` | Ninguna prueba cortaba una cabecera de DARE 1.0 entre dos Write con paquetes pequeños (`PayloadSize` 1). Con el mutante se copian bytes del paquete siguiente y `Write` hace panic |
| `writer-v1.go:236`, `writer-v2.go:120`, `writer-v2.go:232` (3): `w.closeErr == nil` | `TestEncryptWriter_ClosableDestinationError`, `TestDecryptWriter_ClosableDestinationError` | Los mocks de `dst` no eran `io.Closer`. Con el mutante, si `dst` se cierra bien, `Close` pierde el error de la última escritura y devuelve `nil` |

Estas pruebas no encontraron bugs. Pero al revisar el mutante vivo de `sio.go:287` apareció uno: `DecryptBuffer` con solo la versión 2.0 hace panic con un flujo cortado. Lo detecta `TestDecryptBuffer_ShortInput` y está en la issue #12.

## Mutantes vivos

### Comprobaciones

- **Ninguno muere con las pruebas saltadas.** Se aplicó cada mutante vivo a mano y se ejecutaron todas las pruebas, también las de los bugs abiertos: ninguno hace fallar una prueba que antes pasaba. Así que ninguno está vivo solo porque su prueba se salta. El de `sio.go:287` hace lo contrario: hace pasar dos subtests saltados del bug #12 (ver abajo).
- **Pruebas aleatorias con paquetes pequeños.** Se aplicó cada mutante vivo y se ejecutaron 1000 casos aleatorios: `PayloadSize` de 1 a 64 KiB (DARE 1.0), tamaño del texto plano y tamaño de cada `Read` y `Write` aleatorios, comparando con `Encrypt` y con el texto plano. Solo murió `writer-v1.go:56`, que ahora mata `TestDecryptWriter_SmallPackagesSplitWrites`. Estas pruebas aleatorias no se guardaron, porque no matan ningún otro mutante.

### Equivalentes (45)

Un mutante es equivalente si cambia el código pero no el resultado que promete la API pública. Ninguna prueba puede matarlo.

Regla para los errores: la doc de cada función solo promete que un fallo de descifrado es un error de tipo `sio.Error`. El texto del mensaje no está documentado, así que un mutante que cambia solo el mensaje de un `sio.Error` cuenta como equivalente. Las pruebas comprueban el tipo (`assert.ErrorAs`), no el texto.

| Grupo | Mutantes | Por qué es equivalente |
|---|---|---|
| Frontera entre dos caminos del buffer | `reader-v1.go:57,66,85,128,137,164`, `reader-v2.go:91,104,137,189,198,231`, `writer-v1.go:55 (2),57,68,87,107,187,189,204,214`, `writer-v2.go:60,94,162` (25) | Cambian `<` por `<=`, `>=` por `>` o `> 0` por `>= 0` donde los dos caminos dan los mismos bytes. Ejemplo: con `len(p) == remaining`, un camino copia el resto del paquete y el otro copia lo mismo y después copia 0 bytes. Solo cambia por dónde pasa el código |
| Leer 0 bytes de más | `reader-v1.go:236`, `reader-v2.go:322` (2) | `k > 0` -> `k >= 0`: con `k == 0`, `io.CopyN` no lee nada |
| Reserva de memoria | `reader-v2.go:250,256`, `sio.go:243` (3) | Solo cambian cuándo se reserva un buffer o su tamaño. El resultado es el mismo |
| Comprobación repetida | `dare.go:238 (2)`, `writer-v1.go:125 (3),130 (4),133`, `writer-v2.go:219`, `generic.go:122` (12) | Si el mutante quita la comprobación, una comprobación posterior da también un `sio.Error` (a veces con otro mensaje). Ejemplo: en `decWriterV10.Close`, un paquete incompleto falla en la línea 125 o, si no, en la 130 o en `Open` |
| Condición que no puede cambiar | `reader-v1.go:247`, `reader-v2.go:333`, `sio.go:405` (3) | `ReadAt` nunca recibe `io.EOF` con `p` lleno (ver `coverage.md`). Con `MinVersion == 1.0`, asignar 1.0 no cambia nada |

### Observables, pero sin resultado especificado (4)

Estos mutantes cambian algo que se puede observar, pero ninguna documentación dice cuál es el resultado correcto, así que no hay un valor esperado para una prueba.

| Mutantes | Qué cambia |
|---|---|
| `generic.go:106,111` (2) | La primera lectura del lector genérico devuelve `0, nil` y las siguientes, los datos. La doc de `io.Reader` lo desaconseja ("discouraged"), pero no lo prohíbe |
| `sio.go:55` (2) | Cambian la detección de AES por hardware. Con la configuración por defecto, el flujo usa ChaCha20 en lugar de AES-GCM (se ve en el byte 1 de la cabecera). Los dos cifrados son correctos y la doc de `Config` no dice cuál debe usarse por defecto |

### Cambia solo el resultado de un bug abierto (1)

| Mutantes | Qué cambia |
|---|---|
| `sio.go:287` (1) | La condición pasa a ser siempre falsa y `DecryptBuffer` con solo la versión 2.0 usa el camino genérico. Con un flujo cortado de menos de 16 bytes, el código original hace panic (issue #12) y el mutante devuelve un `sio.Error`. La prueba que lo nota, `TestDecryptBuffer_ShortInput/2.0`, falla por el bug y el script la salta. Con los demás flujos, el resultado es el mismo |
