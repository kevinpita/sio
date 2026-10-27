#!/usr/bin/env bash
# Pruebas de mutación de la biblioteca con gremlins.
#
# 1. Los subtests que fallan por bugs abiertos (reports/known-failures.txt, con
#    su issue) se saltan con -skip. Si no, gremlins vería un fallo con cualquier
#    mutante y lo daría por muerto. Antes se comprueba que el resto pasa: un
#    fallo nuevo para el script.
# 2. gremlins se ejecuta en una copia de los ficheros del repositorio: no puede
#    copiar el directorio .devenv.
# 3. -count=1: sin la caché de go test, gremlins mide bien el tiempo de las
#    pruebas, que usa para el tiempo límite de cada mutante.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

skip=$(grep '^Test' reports/known-failures.txt | python3 -c '
import re, sys
element = lambda s: "^" + re.escape(s) + "$"
print("|".join("/".join(map(element, t.strip().split("/"))) for t in sys.stdin))
')
go test -count=1 -skip "$skip" . > /dev/null || { echo "hay pruebas que fallan y no están en known-failures.txt" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git ls-files -z | xargs -0 cp --parents -t "$work"
cd "$work"
GOFLAGS="-count=1 -skip=$skip" gremlins unleash --workers 8 --timeout-coefficient 10 -S lt .
