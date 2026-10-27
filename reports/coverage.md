# Análisis de cobertura

Fila 7 de la rúbrica. La cobertura no llega al 100 %. Este informe justifica cada línea y cada condición que las pruebas no ejecutan.

## Comandos

```sh
# Biblioteca: cobertura de sentencias
go test -covermode=set -coverprofile=reports/cover.out .
go tool cover -func=reports/cover.out

# Biblioteca: cobertura de condiciones (cada parte de un && o || en verdadero y en falso)
gobco .

# ncrypt: el programa se prueba como binario. Con GOCOVERDIR, TestMain lo compila con -cover
mkdir /tmp/nc
GOCOVERDIR=/tmp/nc go test ./cmd/ncrypt
go tool covdata percent -i /tmp/nc
```

Hay pruebas que fallan a propósito (issues #1 a #9). Go guarda la cobertura aunque una prueba falle.

## Resultado

| Parte | Medida | Antes | Después |
|---|---|---|---|
| Biblioteca (`sio`) | sentencias | 87,5 % | 93,5 % |
| Biblioteca (`sio`) | condiciones (`gobco`) | 502/570 | 504-506/570 (88 %) |
| `cmd/ncrypt` | sentencias | sin medir | 77,5 % |

El número de condiciones cambia un poco entre ejecuciones porque las pruebas con datos aleatorios (`rapid`) no siempre pasan por los mismos caminos.

## Pruebas añadidas a partir de la cobertura

Las líneas sin cubrir que se pueden alcanzar desde la API pública tienen ahora una prueba. Ninguna de estas pruebas nuevas encontró un bug.

| Línea antes sin cubrir | Prueba |
|---|---|
| `sio.go:384-395` (versión desconocida, más de 2 cifrados) | 3 filas nuevas en `invalidConfigs`: `min version above 2.0`, `max version above 2.0`, `two known ciphers and one unknown` |
| `dare.go:250,256,264`, `reader-v1.go:177,185`, `writer-v1.go:130` | filas nuevas en `tamperings`: `first package cut`, `second header cut`, `second package cut after the header`, `second header cipher changed`, `second header byte 4 changed`, `second header byte 8 changed` |
| `dare.go:235` (datos detrás del paquete final) | `TestDecryptReader_DataAfterEnd` |
| `reader-v2.go:200` (falta el último paquete) | `TestDecryptReader_LastPackageRemoved` |
| `reader-v2.go:107` (fallo de la fuente con un buffer grande) | `TestEncryptReader_SourceError`, con buffers de 1 byte y de un paquete |
| `generic.go:43,92,160`, `writer-v2.go:94` (Read o Write de 0 bytes) | `TestDecryptReader_EmptyRead`, `TestDecryptReaderAt_EmptyRead`, `TestDecryptWriter_EmptyWrite`, `TestEncryptWriter_EmptyWrite` |
| `generic.go:48,169` (byte de versión desconocido) | `TestDecryptReaderAt_UnknownVersion`, `TestDecryptWriter_UnknownVersion` |
| `generic.go:131` (DecryptBuffer 1.0 con la configuración por defecto) | `TestDecryptBuffer_TamperedDefaultConfig` |
| `generic.go:42` (segundo Write del escritor genérico) | `TestDecryptWriter_DefaultConfig`, ahora también en varios Write |
| `writer-v1.go:74,79,196`, `writer-v2.go:72,168,173` (errores con datos en el buffer) | `*Writer_DestinationError` y `TestDecryptWriter_Tampered`, ahora también con Writes de 1000 bytes (`writeChunks`) |
| `writer-v1.go:52,117,184,224`, `writer-v2.go:52,104,157,211` (estado después de un error) | `TestEncryptWriter_WriteAfterError`, `TestEncryptWriter_CloseAfterError`, `TestDecryptWriter_WriteAfterError`, `TestDecryptWriter_CloseAfterError` |
| `cmd/ncrypt/main.go:75-81` (ayuda) | `TestNcrypt_Help` |
| `cmd/ncrypt/main.go:88-90,175-192,263-266` (errores con ficheros) | 3 filas nuevas en `TestNcrypt_Errors` y `TestNcrypt_OutputRemovedOnError` |

## Líneas sin cubrir y justificación

### Biblioteca

| Líneas | Motivo |
|---|---|
| `dare.go:69` (`packageV20.Ciphertext`) | Código muerto: ninguna función llama a este método. |
| `sio.go:55-67`, `sio.go:377-380` (`detectAESSupport`, `defaultCipherSuites`) | Dependen del procesador. En esta máquina (amd64 con AES-NI) solo se ejecuta una rama. Las demás solo se ejecutan en arm64, s390x o en un procesador sin AES. |
| `dare.go:89,123,168,221`, `sio.go:82,120` | Errores al crear el cifrado (`aes.NewCipher`, `chacha20poly1305.New`, `HChaCha20`). Solo fallan con una clave de tamaño incorrecto, y `setConfigDefaults` ya rechaza esas claves antes. |
| `reader-v1.go:109,204`, `reader-v2.go:171,244,285`, `writer-v1.go:38`, `writer-v2.go:144`, `generic.go:52,57,106,111,173,178` | Errores de los constructores internos. Solo fallan por los motivos de la fila anterior, y la Config ya se validó antes de llamarlos. |
| `dare.go:191`, `reader-v2.go:111,117,132,145`, `writer-v2.go:67,81,112` | `Seal` solo falla si se llama después del paquete final (`errSealAfterFinal`). Los lectores y escritores no lo hacen nunca: después del paquete final no cifran más. |
| `dare.go:146` | La longitud del paquete 1.0 siempre coincide: el lector lee exactamente los bytes que dice la cabecera antes de llamar a `Open`. |
| `reader-v1.go:247`, `reader-v2.go:333` | `ReadAt` cambia `io.EOF` por `nil` si ya leyó todo `p`. `decReaderV10.Read` y `decReaderV20.Read` nunca devuelven datos junto con `io.EOF`, así que el caso no ocurre. |
| `writer-v1.go:133-138` | `decWriterV10.Write` descifra cada paquete en cuanto lo tiene completo. En `Close` nunca queda un paquete completo en el buffer, así que siempre se cumple la condición de la línea 130. |
| `writer-v1.go:248` | `flush` comprueba que `dst` escribió todo. La doc de `io.Writer` obliga a devolver un error si escribe menos, así que solo falla con un `dst` que no cumple la doc. |
| `writer-v1.go:118,142-145,225`, `writer-v2.go:105,212,231-234` | Cerrar `dst` si es un `io.Closer`. La doc de `EncryptWriter` y `DecryptWriter` no dice que `Close` cierre `dst`, así que no hay resultado esperado para probarlo. Con `EncryptWriter`, el caso sin error sí se ejecuta en `TestIntegration_Pipe`. |

### Condiciones (`gobco`) que no son líneas de la tabla anterior

| Condición | Motivo |
|---|---|
| `sio.go:287,317,334,370`: `config.MaxVersion == Version20` nunca es falso | Se evalúa solo si `MinVersion == Version20`. Con `MaxVersion` menor, `setConfigDefaults` ya devolvió error (mínimo mayor que máximo). |
| `writer-v1.go:236`, `writer-v2.go:120`: `w.closeErr == nil` nunca es falso | Mismo motivo que cerrar `dst` en la tabla anterior. |

### `cmd/ncrypt`

| Líneas | Motivo |
|---|---|
| `main.go:198-223`, `main.go:234-237` (`readPassword`) | Lee la contraseña de un terminal interactivo. Las pruebas ejecutan el programa sin terminal y usan `-p`. |
| `main.go:245` | `crypto/rand` no falla en un sistema normal. |
| `main.go:249` | Escribir la sal en el fichero de salida solo falla si el disco está lleno (por ejemplo `/dev/full`, que solo existe en Linux). |
| `main.go:255` | `scrypt.Key` solo falla con parámetros no válidos, y el programa usa parámetros fijos y válidos. |
