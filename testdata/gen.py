"""Genera las salidas cifradas de referencia de testdata/.

La versión 1.0 sigue DARE.md, sección 4. La 2.0 sigue testdata/V2.md.
No usa sio: es una implementación independiente con otra biblioteca de
cifrado, así que las pruebas comparan sio con la especificación.

Uso: python3 testdata/gen.py   (o `vvs-golden` dentro de devenv)
"""

from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = bytes(32)                  # clave de 32 bytes a cero
NONCE = bytes(range(1, 13))      # 1, 2, ..., 12 (fixedNonce en fixtures_test.go)
PAYLOAD = 64 * 1024              # tamaño máximo de payload por paquete
SIZES = [0, 1, PAYLOAD - 1, PAYLOAD, PAYLOAD + 1]
AES_GCM = 0x00


def test_data(n):
    """Igual que testData en fixtures_test.go: 0, 1, ..., 250, 0, 1, ..."""
    return bytes(i % 251 for i in range(n))


def chunks(data):
    return [data[i:i + PAYLOAD] for i in range(0, len(data), PAYLOAD)]


def encrypt_v10(plaintext):
    out = b""
    for seq, chunk in enumerate(chunks(plaintext)):
        header = (bytes([0x10, AES_GCM])
                  + (len(chunk) - 1).to_bytes(2, "little")
                  + seq.to_bytes(4, "little")
                  + NONCE[:8])
        out += header + AESGCM(KEY).encrypt(header[4:16], chunk, header[0:4])
    return out


def encrypt_v20(plaintext):
    out = b""
    packages = chunks(plaintext)
    for seq, chunk in enumerate(packages):
        final = seq == len(packages) - 1
        first = NONCE[0] | 0x80 if final else NONCE[0] & 0x7F
        header = (bytes([0x20, AES_GCM])
                  + (len(chunk) - 1).to_bytes(2, "little")
                  + bytes([first]) + NONCE[1:])
        counter = int.from_bytes(header[12:16], "little") ^ seq
        nonce = header[4:12] + counter.to_bytes(4, "little")
        out += header + AESGCM(KEY).encrypt(nonce, chunk, header[0:4])
    return out


for version, encrypt in [("1.0", encrypt_v10), ("2.0", encrypt_v20)]:
    for size in SIZES:
        path = Path(__file__).parent / f"v{version}_{size}.dare"
        path.write_bytes(encrypt(test_data(size)))
