#!/usr/bin/env python3
"""Captura paquetes DNS en una interfaz y los guarda en formato pcap.

Pensado para ejecutarse dentro del espacio de red del laboratorio:
    python3 dns_capture.py capturas/dns-lab.pcap lo

Se detiene con Ctrl-C / SIGTERM y deja el archivo pcap listo para Wireshark.
"""

import signal
import socket
import struct
import sys
import time

RUNNING = True


def _stop(signum, frame):
    global RUNNING
    RUNNING = False


def es_dns(frame):
    if len(frame) < 34:
        return False
    if frame[12:14] != b"\x08\x00":
        return False

    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    if len(ip) < ihl + 4:
        return False
    if ip[9] not in (6, 17):
        return False

    sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
    return sport == 53 or dport == 53


def main():
    if len(sys.argv) < 2:
        print("uso: dns_capture.py <salida.pcap> [interfaz]", file=sys.stderr)
        return 1

    salida = sys.argv[1]
    interfaz = sys.argv[2] if len(sys.argv) > 2 else "lo"

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((interfaz, 0))
    sock.settimeout(0.3)

    capturados = 0

    with open(salida, "wb") as archivo:
        # Cabecera global pcap: little-endian, microsegundos, enlace Ethernet.
        archivo.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        while RUNNING:
            try:
                frame, direccion = sock.recvfrom(65535)
            except socket.timeout:
                continue

            # En loopback cada paquete se ve dos veces (saliente y entrante);
            # se conserva solo la copia entrante.
            if len(direccion) > 2 and direccion[2] == socket.PACKET_OUTGOING:
                continue

            if not es_dns(frame):
                continue

            ahora = time.time_ns()
            segundos, nanosegundos = divmod(ahora, 1_000_000_000)
            microsegundos = nanosegundos // 1000

            archivo.write(struct.pack("<IIII", segundos, microsegundos,
                                      len(frame), len(frame)))
            archivo.write(frame)
            archivo.flush()
            capturados += 1

    print(f"Capturados {capturados} paquetes DNS en {salida}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
