#!/usr/bin/env bash
set -euo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CTRL="$LAB/.control"

usage() {
    cat <<EOF
Uso: $0 <comando>

  start            Levanta el laboratorio (root, unsigned, alpha, recursive1)
  stop             Detiene el laboratorio
  status           Muestra el estado de los procesos
  test             Ejecuta consultas de verificacion
  dig <args>       Ejecuta dig dentro del laboratorio, ej: $0 dig www.alpha.unsigned
  exec <comando>   Ejecuta un comando dentro del espacio de red del laboratorio
  logs [servidor]  Muestra los logs (root|unsigned|alpha|recursive1)
EOF
}

send() {
    local cmd="$1"
    if [[ ! -f "$CTRL/ready" ]]; then
        echo "El laboratorio no esta corriendo. Use: $0 start" >&2
        exit 1
    fi

    rm -f "$CTRL/out"
    printf '%s' "$cmd" >"$CTRL/cmd.tmp"
    mv "$CTRL/cmd.tmp" "$CTRL/cmd"

    for _ in $(seq 1 600); do
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
        if [[ -f "$CTRL/ready" ]] && [[ -f "$LAB/.lab.pid" ]] &&
           kill -0 "$(cat "$LAB/.lab.pid")" 2>/dev/null; then
            echo "El laboratorio ya esta corriendo."
            exit 0
        fi

        rm -rf "$CTRL"
        mkdir -p "$CTRL"

        nohup unshare -Urn --fork bash "$LAB/bin/lab-ns.sh" "$LAB" \
            >"$LAB/lab.log" 2>&1 &
        echo $! >"$LAB/.lab.pid"

        for _ in $(seq 1 150); do
            if [[ -f "$CTRL/ready" ]]; then
                echo "Laboratorio levantado."
                do_test
                exit 0
            fi
            if ! kill -0 "$(cat "$LAB/.lab.pid")" 2>/dev/null; then
                echo "Fallo el arranque del laboratorio:" >&2
                cat "$LAB/lab.log" >&2
                exit 1
            fi
            sleep 0.2
        done

        echo "Timeout esperando el arranque del laboratorio:" >&2
        cat "$LAB/lab.log" >&2
        exit 1
        ;;
    stop)
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
        ;;
    status)
        if [[ -f "$CTRL/ready" ]] && [[ -f "$LAB/.lab.pid" ]] &&
           kill -0 "$(cat "$LAB/.lab.pid")" 2>/dev/null; then
            echo "Laboratorio activo (red aislada sin privilegios)."
            send 'ps -o pid,comm,args -C named'
        else
            echo "Laboratorio detenido."
        fi
        ;;
    test)
        do_test
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
