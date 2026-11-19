#!/usr/bin/env bash
set -euo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CTRL="$LAB/.control"
PCAP="$LAB/captures/dns-lab.pcap"

usage() {
    cat <<EOF
Uso: $0 <comando>

  start            Levanta el laboratorio (root, unsigned, alpha, recursive1)
  stop             Detiene el laboratorio
  status           Muestra el estado de los procesos
  test             Ejecuta consultas de verificacion
  capture          Reinicia en frio, captura trafico DNS y genera la traza pcap
  analyze [traza]  Analiza una traza pcap (por defecto captures/dns-lab.pcap)
  dig <args>       Ejecuta dig dentro del laboratorio, ej: $0 dig www.alpha.unsigned
  exec <comando>   Ejecuta un comando dentro del espacio de red del laboratorio
  logs [servidor]  Muestra los logs (root|unsigned|alpha|recursive1)
EOF
}

is_running() {
    [[ -f "$CTRL/ready" ]] && [[ -f "$LAB/.lab.pid" ]] &&
        kill -0 "$(cat "$LAB/.lab.pid")" 2>/dev/null
}

send() {
    local cmd="$1"
    if ! is_running; then
        echo "El laboratorio no esta corriendo. Use: $0 start" >&2
        exit 1
    fi

    rm -f "$CTRL/out"
    printf '%s' "$cmd" >"$CTRL/cmd.tmp"
    mv "$CTRL/cmd.tmp" "$CTRL/cmd"

    for _ in $(seq 1 900); do
        if [[ -f "$CTRL/out" ]]; then
            cat "$CTRL/out"
            rm -f "$CTRL/out"
            return 0
        fi
        sleep 0.1
    done

    echo "Timeout esperando la respuesta del laboratorio" >&2
    exit 1
}

start_lab() {
    if is_running; then
        echo "El laboratorio ya esta corriendo."
        return 0
    fi

    rm -rf "$CTRL"
    mkdir -p "$CTRL"

    nohup unshare -Urn --fork bash "$LAB/bin/lab-ns.sh" "$LAB" \
        >"$LAB/lab.log" 2>&1 &
    echo $! >"$LAB/.lab.pid"

    for _ in $(seq 1 150); do
        if [[ -f "$CTRL/ready" ]]; then
            echo "Laboratorio levantado."
            return 0
        fi
        if ! kill -0 "$(cat "$LAB/.lab.pid")" 2>/dev/null; then
            echo "Fallo el arranque del laboratorio:" >&2
            cat "$LAB/lab.log" >&2
            return 1
        fi
        sleep 0.2
    done

    echo "Timeout esperando el arranque del laboratorio:" >&2
    cat "$LAB/lab.log" >&2
    return 1
}

stop_lab() {
    if [[ -f "$CTRL/ready" ]]; then
        touch "$CTRL/stop"
        for _ in $(seq 1 50); do
            [[ -f "$CTRL/ready" ]] || break
            sleep 0.1
        done
    fi
    if [[ -f "$LAB/.lab.pid" ]]; then
        kill "$(cat "$LAB/.lab.pid")" 2>/dev/null || true
        rm -f "$LAB/.lab.pid"
    fi
    echo "Laboratorio detenido."
}

do_test() {
    send '
echo "== SOA de la raiz (autoritativo) =="
dig +time=2 +tries=1 @172.30.0.10 . SOA +short
echo
echo "== Delegacion unsigned. en la raiz =="
dig +time=2 +tries=1 @172.30.0.10 unsigned. NS +noall +authority +additional
echo
echo "== Delegacion alpha.unsigned. en unsigned =="
dig +time=2 +tries=1 @172.30.0.20 alpha.unsigned. NS +noall +authority +additional
echo
echo "== www.alpha.unsigned. en el autoritativo alpha =="
dig +time=2 +tries=1 @172.30.0.30 www.alpha.unsigned. A +short
echo
echo "== www.alpha.unsigned. via recursivo 172.30.0.100 =="
dig +time=2 +tries=1 @172.30.0.100 www.alpha.unsigned. A +short
echo
echo "== Respuesta completa del recursivo =="
dig +time=2 +tries=1 @172.30.0.100 www.alpha.unsigned. A
'
}

case "${1:-}" in
    start)
        start_lab
        do_test
        ;;
    stop)
        stop_lab
        ;;
    status)
        if is_running; then
            echo "Laboratorio activo (red aislada sin privilegios)."
            send 'ps -o pid,comm,args -C named'
        else
            echo "Laboratorio detenido."
        fi
        ;;
    test)
        do_test
        ;;
    capture)
        stop_lab >/dev/null
        start_lab
        send "bash \"$LAB/bin/capture-run.sh\" \"$LAB\""
        echo
        echo "Traza guardada en: $PCAP"
        echo "Para abrirla en Wireshark: wireshark \"$PCAP\""
        ;;
    analyze)
        traza="${2:-$PCAP}"
        if [[ ! -f "$traza" ]]; then
            echo "No existe la traza: $traza" >&2
            exit 1
        fi
        python3 "$LAB/bin/dns_analyze.py" "$traza"
        ;;
    dig)
        shift
        args="$*"
        if [[ "$args" != *"@"* ]]; then
            args="@172.30.0.100 $args"
        fi
        send "dig $args"
        ;;
    exec)
        shift
        send "$*"
        ;;
    logs)
        server="${2:-}"
        if [[ -n "$server" ]]; then
            cat "$LAB/$server/named.log"
        else
            for server in root unsigned alpha recursive1; do
                echo "===== $server ====="
                tail -n 15 "$LAB/$server/named.log" 2>/dev/null || true
            done
        fi
        ;;
    *)
        usage
        exit 1
        ;;
esac
