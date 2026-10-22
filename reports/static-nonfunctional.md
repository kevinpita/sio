# Análisis estático no funcional

Fila 3 (tipo CheckStyle) de la rúbrica. Código de la biblioteca y de `cmd/ncrypt`, sin los ficheros de pruebas.

## `gofmt -l`

```text
(sin hallazgos)
```

## `staticcheck -tests=false -checks "ST*" ./...`

```text
sio.go:44:2: should not use ALL_CAPS in Go names; use CamelCase instead (ST1003)
sio.go:46:2: should not use ALL_CAPS in Go names; use CamelCase instead (ST1003)
```

## `gocyclo -over 10`

Complejidad ciclomática.

```text
26 sio (*encReaderV20).Read reader-v2.go:70:1
17 sio (*decReaderV20).Read reader-v2.go:183:1
15 sio setConfigDefaults sio.go:383:1
14 sio (*decWriterV10).Write writer-v1.go:51:1
14 sio (*authDecV20).Open dare.go:234:1
11 sio (*decWriterV20).Write writer-v2.go:156:1
11 sio (*encWriterV20).Write writer-v2.go:51:1
11 sio (*decWriterV10).Close writer-v1.go:114:1
11 sio (*decReaderAtV20).ReadAt reader-v2.go:296:1
11 sio (*decReaderV10).Read reader-v1.go:121:1
11 sio (*encReaderV10).Read reader-v1.go:50:1
```

## `golangci-lint run --config reports/golangci-nonfunctional.yml --tests=false ./...`

Analizadores: revive, gocritic, misspell, gocyclo (> 15), gocognit (> 20), funlen, godot, dupl, nestif, lll y govet fieldalignment.

```text
writer-v1.go:51:24: Function 'Write' has too many statements (48 > 40) (funlen)
reader-v2.go:70:1: cognitive complexity 39 of func `(*encReaderV20).Read` is high (> 20) (gocognit)
reader-v2.go:183:1: cognitive complexity 25 of func `(*decReaderV20).Read` is high (> 20) (gocognit)
cmd/ncrypt/main.go:161:1: unnamedResult: consider giving a name to these results (gocritic)
cmd/ncrypt/main.go:262:33: hugeParam: cfg is heavy (96 bytes); consider passing it by pointer (gocritic)
cmd/ncrypt/main.go:269:33: hugeParam: cfg is heavy (96 bytes); consider passing it by pointer (gocritic)
dare.go:50:30: importShadow: shadow of imported package 'cipher' (gocritic)
dare.go:88:2: importShadow: shadow of imported package 'cipher' (gocritic)
dare.go:167:2: importShadow: shadow of imported package 'cipher' (gocritic)
dare.go:271:2: importShadow: shadow of imported package 'cipher' (gocritic)
reader-v2.go:43:1: unnamedResult: consider giving a name to these results (gocritic)
reader-v2.go:228:6: sloppyReassign: re-assignment to `err` can be replaced with `err := r.Open(r.buffer[headerSize:], r.buffer[:nn])` (gocritic)
reader-v2.go:263:6: sloppyReassign: re-assignment to `err` can be replaced with `err := ad.Open(dst[len(dst)-payloadLen:], buffer)` (gocritic)
sio.go:238:44: hugeParam: config is heavy (96 bytes); consider passing it by pointer (gocritic)
sio.go:257:44: hugeParam: config is heavy (96 bytes); consider passing it by pointer (gocritic)
sio.go:276:37: hugeParam: config is heavy (96 bytes); consider passing it by pointer (gocritic)
sio.go:296:35: hugeParam: config is heavy (96 bytes); consider passing it by pointer (gocritic)
sio.go:310:35: hugeParam: config is heavy (96 bytes); consider passing it by pointer (gocritic)
sio.go:327:39: hugeParam: config is heavy (96 bytes); consider passing it by pointer (gocritic)
sio.go:346:35: hugeParam: config is heavy (96 bytes); consider passing it by pointer (gocritic)
sio.go:363:35: hugeParam: config is heavy (96 bytes); consider passing it by pointer (gocritic)
sio.go:36:1: Comment should end in a period (godot)
sio.go:38:1: Comment should end in a period (godot)
sio.go:139:1: Comment should end in a period (godot)
sio.go:142:1: Comment should end in a period (godot)
dare.go:72:14: fieldalignment: authEnc has 32 leading bytes of pointer data but optimal value is 24 (govet)
dare.go:79:14: fieldalignment: authDec has 40 leading bytes of pointer data but optimal value is 32 (govet)
generic.go:22:16: fieldalignment: decWriter has 112 leading bytes of pointer data but optimal value is 104 (govet)
generic.go:72:16: fieldalignment: decReader has 112 leading bytes of pointer data but optimal value is 104 (govet)
generic.go:140:18: fieldalignment: decReaderAt has 112 leading bytes of pointer data but optimal value is 104 (govet)
reader-v1.go:22:19: fieldalignment: encReaderV10 has 128 leading bytes of pointer data but optimal value is 96 (govet)
reader-v1.go:95:19: fieldalignment: decReaderV10 has 112 leading bytes of pointer data but optimal value is 88 (govet)
reader-v2.go:23:19: fieldalignment: encReaderV20 has size 144 but the optimal size is 136 (allocator size class 144) (govet)
reader-v2.go:157:19: fieldalignment: decReaderV20 has 136 leading bytes of pointer data but optimal value is 112 (govet)
sio.go:159:13: fieldalignment: Config has size 96 but the optimal size is 88 (allocator size class 96) (govet)
writer-v1.go:21:19: fieldalignment: decWriterV10 has 112 leading bytes of pointer data but optimal value is 88 (govet)
writer-v1.go:150:19: fieldalignment: encWriterV10 has 128 leading bytes of pointer data but optimal value is 96 (govet)
writer-v2.go:21:19: fieldalignment: encWriterV20 has 128 leading bytes of pointer data but optimal value is 96 (govet)
writer-v2.go:127:19: fieldalignment: decWriterV20 has 144 leading bytes of pointer data but optimal value is 112 (govet)
cmd/ncrypt/main.go:73:1: The line is 122 characters long, which exceeds the maximum of 120 characters. (lll)
dare.go:32:1: The line is 145 characters long, which exceeds the maximum of 120 characters. (lll)
dare.go:52:1: The line is 139 characters long, which exceeds the maximum of 120 characters. (lll)
dare.go:272:1: The line is 128 characters long, which exceeds the maximum of 120 characters. (lll)
reader-v1.go:144:1: The line is 132 characters long, which exceeds the maximum of 120 characters. (lll)
reader-v1.go:159:1: The line is 129 characters long, which exceeds the maximum of 120 characters. (lll)
writer-v1.go:55:1: The line is 129 characters long, which exceeds the maximum of 120 characters. (lll)
writer-v2.go:80:1: The line is 139 characters long, which exceeds the maximum of 120 characters. (lll)
reader-v2.go:123:1: `if len(p) > 0` has complex nested blocks (complexity: 9) (nestif)
reader-v2.go:216:1: `if len(p) > 0` has complex nested blocks (complexity: 5) (nestif)
writer-v1.go:124:1: `if w.offset > 0` has complex nested blocks (complexity: 8) (nestif)
sio.go:44:2: var-naming: don't use ALL_CAPS in Go names; use CamelCase (revive)
sio.go:46:2: var-naming: don't use ALL_CAPS in Go names; use CamelCase (revive)
52 issues:
* funlen: 1
* gocognit: 2
* gocritic: 18
* godot: 4
* govet: 14
* lll: 8
* nestif: 3
* revive: 2
```

## Revisión manual de los comentarios de documentación

Los analizadores comprueban la forma de los comentarios (godot, revive), no su contenido. Se leyeron los comentarios de la API pública de `sio.go` y se compararon con el código y con las pruebas.

- `sio.go:172` `Config.Key`: "It must be 32 bytes long". El código acepta también claves de 16 bytes con los dos cifrados (`sio.go:390`, `sio.go:111-123`), y la doc de `AES_GCM` (`sio.go:43`) habla de claves de 128 bits. El caso `128-bit key` de las pruebas `*_ValidConfig` pasa.
- `sio.go:45` `CHACHA20_POLY1305`: "with 256 bit keys". Correcto: con una clave de 16 bytes, `newChaCha20` deriva una clave de 256 bits con HChaCha20 antes de crear el cifrado (`sio.go:89-110`).

## Clasificación de los hallazgos

| Hallazgo | Clase | Motivo |
|---|---|---|
| gocyclo 26 / gocognit 39 `(*encReaderV20).Read`, gocyclo 17 / gocognit 25 `(*decReaderV20).Read`, nestif `reader-v2.go:123,216` | Real, issue #10 | Superan con mucho el umbral habitual de complejidad (15 ciclomática, 20 cognitiva). Las dos funciones repiten la misma lógica en dos ramas: una escribe en `p` directamente y otra pasa por el buffer interno. |
| gocyclo 11-15 (9 funciones), funlen `writer-v1.go:51`, nestif `writer-v1.go:124` | Aceptado | Entre 10 y 15, dentro del rango que se considera manejable. Son lectores y escritores de flujos con muchos casos de error. |
| Doc de `Config.Key` (revisión manual) | Real, issue #11 | La doc dice 32 bytes, pero se aceptan 16. Contradice la doc de `AES_GCM`. |
| ST1003 / revive var-naming `sio.go:44,46` (`AES_GCM`, `CHACHA20_POLY1305`) | Aceptado | Son constantes de la API pública. Cambiar el nombre rompe a todos los usuarios de la biblioteca. Los nombres siguen los nombres de los algoritmos. |
| gocritic hugeParam `Config` por valor (96 bytes), `sio.go` y `cmd/ncrypt` | Aceptado | Las firmas de la API pública reciben `Config` por valor. Pasar a puntero rompe la API. Se copia una vez por llamada, no por paquete. |
| govet fieldalignment (14) | Aceptado, beneficio no medido | 2 avisos de tamaño (`Config` 96 -> 88, `encReaderV20` 144 -> 136): sin ahorro cuando el struct se reserva solo en el heap, porque la clase de tamaño del asignador es la misma. 12 avisos de orden de punteros: menos trabajo del recolector de basura, no medido. Reordenar `Config` no cambia la API, pero sí el orden de los campos en la doc. |
| gocritic importShadow `dare.go` (variable `cipher`) | Aceptado | La variable tapa el paquete `crypto/cipher` solo dentro de la función, y la función no usa el paquete. |
| gocritic unnamedResult, sloppyReassign | Aceptado | Preferencias de estilo sin efecto en la lectura del código. |
| godot `sio.go:36,38,139,142` | Aceptado | Comentarios sin punto final. Dos son comentarios de grupo internos. |
| lll (8 líneas de 122 a 145 caracteres) | Aceptado | Funciones de una línea en `dare.go` y comentarios largos. gofmt no las parte. |
| gofmt, misspell, dupl | Sin hallazgos | - |
