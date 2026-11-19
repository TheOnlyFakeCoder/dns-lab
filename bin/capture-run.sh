#!/usr/bin/env bash
set -euo pipefail

LAB="${1:?uso: capture-run.sh <ruta-del-laboratorio>}"
SALIDA="$LAB/captures/dns-lab.pcap"

mkdir -p "$LAB/captures"
rm -f "$SALIDA"

python3 "$LAB/bin/dns_capture.py" "$SALIDA" lo &
CAPTURA_PID=$!
sleep 0.7

consultar() {
    echo ">> dig @172.30.0.100 $*"
    dig +time=2 +tries=1 +noall +answer @172.30.0.100 "$@" || true
    sleep 0.2
}

consultar . SOA
consultar . NS
consultar ns.root. A
consultar unsigned. SOA
consultar unsigned. NS
consultar ns.unsigned. A
consultar alpha.unsigned. SOA
consultar alpha.unsigned. NS
consultar www.alpha.unsigned. A

sleep 0.5
kill -INT "$CAPTURA_PID" 2>/dev/null || true
wait "$CAPTURA_PID" || true

echo
python3 "$LAB/bin/dns_analyze.py" "$SALIDA"
