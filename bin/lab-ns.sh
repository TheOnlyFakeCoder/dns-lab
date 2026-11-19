#!/usr/bin/env bash
set -euo pipefail

LAB="${1:?uso: lab-ns.sh <ruta-del-laboratorio>}"
CTRL="$LAB/.control"

cd "$LAB"

ROOT_IP=172.30.0.10
UNSIGNED_IP=172.30.0.20
ALPHA_IP=172.30.0.30
RECURSIVE_IP=172.30.0.100

PIDS=()

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -f "$CTRL/ready"
}
trap cleanup EXIT INT TERM

ip link set lo up
for ip in "$ROOT_IP" "$UNSIGNED_IP" "$ALPHA_IP" "$RECURSIVE_IP"; do
    ip addr add "$ip/32" dev lo 2>/dev/null || true
done

start_server() {
    local name="$1"
    named -c "$LAB/$name/named.conf" -g >"$LAB/$name/named.log" 2>&1 &
    PIDS+=("$!")
}

start_server root
start_server unsigned
start_server alpha
start_server recursive1

ready=0
for _ in $(seq 1 75); do
    if [[ -n "$(dig +time=1 +tries=1 @$ROOT_IP . SOA +short 2>/dev/null)" ]] &&
       [[ -n "$(dig +time=1 +tries=1 @$UNSIGNED_IP unsigned. SOA +short 2>/dev/null)" ]] &&
       [[ -n "$(dig +time=1 +tries=1 @$ALPHA_IP alpha.unsigned. SOA +short 2>/dev/null)" ]] &&
       [[ "$(dig +time=1 +tries=1 @$RECURSIVE_IP www.alpha.unsigned. A +short 2>/dev/null)" == "172.30.0.30" ]]; then
        ready=1
        break
    fi
    sleep 0.2
done

if [[ "$ready" -ne 1 ]]; then
    echo "ERROR: el laboratorio no arranco correctamente" >&2
    exit 1
fi

touch "$CTRL/ready"

while :; do
    if [[ -f "$CTRL/stop" ]]; then
        rm -f "$CTRL/stop"
        break
    fi

    if [[ -f "$CTRL/cmd" ]]; then
        mv "$CTRL/cmd" "$CTRL/cmd.run" 2>/dev/null || { sleep 0.1; continue; }
        bash -c "$(cat "$CTRL/cmd.run")" >"$CTRL/out.tmp" 2>&1 || true
        mv "$CTRL/out.tmp" "$CTRL/out"
        rm -f "$CTRL/cmd.run"
    fi

    sleep 0.1
done
