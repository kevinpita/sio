# Pruebas no funcionales (rendimiento)

Fila 6 de la rúbrica (tipo JETM). Las herramientas son las de Go: `testing.B` para los benchmarks, `testing.AllocsPerRun` para contar reservas de memoria y [`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) para resumir los benchmarks.

## Requisitos

Salen del README de sio, que es lo único que dice algo sobre rendimiento. RNF-1, RNF-2 y RNF-4 son frases del README. RNF-3 lo definimos nosotros a partir de él: el README dice que el formato admite flujos de hasta 256 TB, pero no dice nada de memoria.

| Id | Requisito (README) | Cómo se comprueba |
|---|---|---|
| RNF-1 | "encryption increases the amount of data by ~0.05%" | Prueba con assert: el tamaño cifrado de 1 MiB, 1 GiB y 256 TiB crece como mucho un 0,05 % |
| RNF-2 | "Random access - arbitrary sequences / ranges can be decrypted independently" | Prueba con assert: leer 1 byte del último paquete con `DecryptReaderAt` lee como mucho un paquete cifrado, con 4 y con 64 paquetes |
| RNF-3 | Definido por nosotros, a partir de "Support for long data streams - up to 256 TB": el número de reservas de memoria no crece con el tamaño del flujo | Prueba con assert: cifrar o descifrar 16 paquetes hace las mismas reservas de memoria que 1 paquete. Motivo: si cada paquete reserva memoria, un flujo de 2^32 paquetes hace miles de millones de reservas |
| RNF-4 | Tabla "Performance": velocidad con cada cifrado y tamaño | Benchmarks sin assert, porque la velocidad depende de la máquina. El resultado se compara con la tabla |

## Pruebas

| Nivel | Fichero | Pruebas |
|---|---|---|
| Unidad | `sio_performance_test.go` | `TestPerformance_SizeOverhead` (RNF-1), `TestPerformance_RandomAccess` (RNF-2), `TestPerformance_Allocations` (RNF-3, `Encrypt` y `Decrypt`), `BenchmarkEncrypt` y `BenchmarkDecrypt` (RNF-4) |
| Integración | `sio_performance_integration_test.go` | `TestIntegration_PipeAllocations` (RNF-3) y `BenchmarkIntegration_PipeRoundTrip` (RNF-4): `EncryptWriter` y `DecryptReader` a la vez en un `io.Pipe` |

Los dos ficheros llevan `//go:build !race`: el detector de carreras cambia el tiempo y las reservas de memoria (por ejemplo, `sync.Pool` tira objetos al azar), así que las medidas no valen con `go test -race`.

```sh
go test -run 'Performance|PipeAllocations' -v .   # pruebas con assert (RNF-1 a RNF-3)
vvs-bench                                         # benchmarks (RNF-4): 10 repeticiones, salida en reports/bench.txt
```

## Resultado de las pruebas con assert

| Requisito | Resultado |
|---|---|
| RNF-1 | Cumple: 32 bytes por cada paquete de 64 KiB, un 0,049 % |
| RNF-2 | Cumple con DARE 1.0 y 2.0 |
| RNF-3 | **No cumple con DARE 2.0** (issue #13, de rendimiento: no es un fallo funcional). Con DARE 1.0 cumple |

**RNF-3 y DARE 2.0:** cifrar o descifrar con DARE 2.0 hace una reserva de memoria más por cada paquete:

| | 1 paquete | 16 paquetes |
|---|---|---|
| `Encrypt`, DARE 1.0 | 9 | 9 |
| `Encrypt`, DARE 2.0 | 10 | 25 |
| `Decrypt`, DARE 2.0 | 10 | 25 |
| `io.Pipe`, DARE 1.0 | 18 | 18 |
| `io.Pipe`, DARE 2.0 | 21 | 51 |

`go build -gcflags=-m` dice por qué: `dare.go:202: moved to heap: nonce` y `dare.go:268: moved to heap: nonce`. En `authEncV20.seal` y `authDecV20.Open`, el array `nonce` se pasa a `cipher.AEAD`, que es una interfaz, así que Go lo pone en el heap en cada paquete. Son 12 bytes por paquete, que el recolector de basura tiene que liberar. La memoria en uso no crece, porque el recolector recicla esas reservas, pero en un flujo de 256 TB son 2^32 reservas de más. Por eso #13 es una mejora de rendimiento (`enhancement`), no un bug: el cifrado funciona bien y ninguna documentación promete cero reservas por paquete.

## Resultado de los benchmarks (RNF-4)

Máquina: AMD Ryzen 7 5800X (con AES-NI), Linux 7.3, Go 1.26.8. Mediana de 10 repeticiones (`reports/bench.txt`). La tabla del README es de un i7-6500U con Go 1.8.

`Encrypt` con la configuración por defecto (DARE 2.0):

| Cifrado | 8 KB | 64 KB | 512 KB | 1 MB |
|---|---|---|---|---|
| AES-GCM, README | 90 MB/s | 1,96 GB/s | 2,64 GB/s | 2,83 GB/s |
| AES-GCM, medido | 837 MB/s | 2,89 GB/s | 4,19 GB/s | 4,31 GB/s |
| ChaCha20-Poly1305, README | 97 MB/s | 1,23 GB/s | 1,54 GB/s | 1,57 GB/s |
| ChaCha20-Poly1305, medido | 849 MB/s | 2,45 GB/s | 3,12 GB/s | 3,19 GB/s |

`Decrypt` da casi lo mismo (AES-GCM 1 MB: 4,39 GB/s, ChaCha20-Poly1305 1 MB: 3,15 GB/s). Cifrar y descifrar a la vez en un `io.Pipe` (integración) llega a 2,40 GB/s con 1 MB, igual con DARE 1.0 y 2.0.

- Todas las medidas están por encima de la tabla del README. La máquina y la versión de Go son más nuevas, así que no es una comparación exacta, pero no hay ninguna pérdida de rendimiento.
- Con 8 KB la velocidad es mucho menor que con 1 MB: cada llamada a `Encrypt` reserva un buffer de 64 KiB (`sio.go:243`) aunque los datos sean pequeños. Es un coste fijo por llamada, no por paquete, así que no incumple RNF-3.
- La reserva de más por paquete de DARE 2.0 (#13) no cambia la velocidad de forma medible: con 1 MB, `io.Pipe` va a 2,40 GB/s con DARE 1.0 y con 2.0.
