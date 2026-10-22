# Análisis estático funcional

Fila 2 (tipo SpotBugs) de la rúbrica. Código de la biblioteca y de `cmd/ncrypt`, sin los ficheros de pruebas.

## `go vet ./...`

```text
(sin hallazgos)
```

## `staticcheck -tests=false -checks all ./...`

```text
sio.go:44:2: should not use ALL_CAPS in Go names; use CamelCase instead (ST1003)
sio.go:46:2: should not use ALL_CAPS in Go names; use CamelCase instead (ST1003)
```

## `gosec -nosec -exclude-dir=.devenv ./...`

`-nosec` muestra también los hallazgos silenciados con `#nosec`. `gosec` suelto no respeta los `//nolint` del código.

```text
[reader-v1.go:235] - G115 (CWE-190): integer overflow conversion int64 -> uint32 (Confidence: MEDIUM, Severity: HIGH)
[dare.go:52] - G115 (CWE-190): integer overflow conversion int -> uint16 (Confidence: MEDIUM, Severity: HIGH)
[dare.go:32] - G115 (CWE-190): integer overflow conversion int -> uint16 (Confidence: MEDIUM, Severity: HIGH)
Summary:
  Files  : 8
  Lines  : 2250
  Nosec  : 0
  Issues : 3
```

## `golangci-lint run --tests=false --enable-only=govet,staticcheck,gosec,errcheck,ineffassign,unused ./...`

Respeta los `//nolint:gosec` del código, por eso no da hallazgos.

```text
0 issues.
```

## `golangci-lint run --config reports/golangci-functional.yml --tests=false ./...`

Más analizadores de bugs: govet con todos sus análisis menos fieldalignment (va a la fila 3), errorlint, forcetypeassert, nilerr, makezero, exhaustive y otros.

```text
reader-v1.go:247:5: comparing with == will fail on wrapped errors. Use errors.Is to check for a specific error (errorlint)
	if err == io.EOF && n == len(p) {
	   ^
reader-v2.go:200:6: comparing with == will fail on wrapped errors. Use errors.Is to check for a specific error (errorlint)
		if err == io.EOF && !r.finalized {
		   ^
reader-v2.go:203:20: comparing with != will fail on wrapped errors. Use errors.Is to check for a specific error (errorlint)
		if err != nil && err != io.ErrUnexpectedEOF {
		                 ^
reader-v2.go:218:6: comparing with == will fail on wrapped errors. Use errors.Is to check for a specific error (errorlint)
		if err == io.EOF && !r.finalized {
		   ^
reader-v2.go:223:20: comparing with != will fail on wrapped errors. Use errors.Is to check for a specific error (errorlint)
		if err != nil && err != io.ErrUnexpectedEOF {
		                 ^
reader-v2.go:333:5: comparing with == will fail on wrapped errors. Use errors.Is to check for a specific error (errorlint)
	if err == io.EOF && n == len(p) {
	   ^
reader-v2.go:44:2: type assertion must be checked (forcetypeassert)
	p := packageBufferPool.Get().(*[]byte)
	^
reader-v1.go:237:9: shadow: declaration of "err" shadows declaration at line 215 (govet)
		if _, err := io.CopyN(io.Discard, &decReader, k); err != nil {
		      ^
reader-v2.go:323:9: shadow: declaration of "err" shadows declaration at line 296 (govet)
		if _, err := io.CopyN(io.Discard, &decReader, k); err != nil {
		      ^
9 issues:
* errorlint: 6
* forcetypeassert: 1
* govet: 2
```

## Clasificación de los hallazgos

| Hallazgo | Clase | Motivo |
|---|---|---|
| gosec G115 `reader-v1.go:235` `uint32(t)` | Bug (issue #9) | La comprobación que protege la conversión (`reader-v1.go:221`, `t+1 > (1<<32)-1`) rechaza el último paquete válido, t = 2^32-1 (DARE.md:98-103). Prueba: `TestDecryptReaderAt_LastPackages`. |
| (sin marca) `reader-v2.go:321` `uint32(t)` | Bug (issue #9) | gosec no lo marca. Revisión manual del mismo punto en DARE 2.0: misma comprobación en `reader-v2.go:302`. La misma prueba falla con 2.0. |
| gosec G115 `dare.go:32`, `dare.go:52` `uint16(length-1)` | Falso positivo | La longitud siempre está entre 1 y 64 KiB: `writer-v2.go:111` solo sella con `w.offset > 0`, `reader-v2.go:111,132` pasan `1+nn` bytes, y DARE 1.0 limita el payload a `PayloadSize <= 64 KiB` (`sio.go:401`). El caso de `PayloadSize` negativo ya está en la issue #1. |
| errorlint `== io.EOF`, `!= io.ErrUnexpectedEOF` (6) | Falso positivo | La doc de `io.Reader` exige que `Read` devuelva `io.EOF` sin envolver, y `io.ReadFull` devuelve los dos errores sin envolver. Comparar con `==` es lo que pide la doc. |
| forcetypeassert `reader-v2.go:44` | Falso positivo | `packageBufferPool` solo guarda valores `*[]byte`, así que la conversión no puede fallar. |
| govet shadow `reader-v1.go:237`, `reader-v2.go:323` | Falso positivo | El `err` interno se devuelve en la misma línea. No cambia el `err` de fuera. |
| staticcheck ST1003 `sio.go:44,46` | Estilo (fila 3) | Nombres `AES_256_GCM` y `CHACHA20_POLY1305` en mayúsculas. No es funcional. |
