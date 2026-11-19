#!/usr/bin/env python3
"""Lee una traza pcap y extrae los registros DNS consultados por dominio.

Uso:
    python3 dns_analyze.py capturas/dns-lab.pcap

No requiere dependencias externas: implementa la lectura de pcap y el
analisis de mensajes DNS (incluida la compresion de nombres).
"""

import socket
import struct
import sys
import time

TIPOS = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 46: "RRSIG",
    47: "NSEC", 48: "DNSKEY", 255: "ANY",
}
CODIGOS = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}
ORDEN_TIPOS = {"SOA": 0, "NS": 1, "A": 2, "AAAA": 3}


class ErrorDNS(Exception):
    pass


def leer_nombre(datos, offset, profundidad=0):
    if profundidad > 20:
        raise ErrorDNS("demasiados punteros de compresion")

    etiquetas = []
    while True:
        if offset >= len(datos):
            raise ErrorDNS("nombre truncado")

        largo = datos[offset]

        if largo == 0:
            offset += 1
            break

        if (largo & 0xC0) == 0xC0:
            if offset + 1 >= len(datos):
                raise ErrorDNS("puntero truncado")
            puntero = ((largo & 0x3F) << 8) | datos[offset + 1]
            subnombre, _ = leer_nombre(datos, puntero, profundidad + 1)
            if subnombre != ".":
                etiquetas.append(subnombre.rstrip("."))
            offset += 2
            break

        if (largo & 0xC0) != 0:
            raise ErrorDNS("etiqueta invalida")

        offset += 1
        if offset + largo > len(datos):
            raise ErrorDNS("etiqueta truncada")

        etiquetas.append(datos[offset:offset + largo].decode("ascii", "replace"))
        offset += largo

    nombre = ".".join(e for e in etiquetas if e)
    return (nombre + "." if nombre else "."), offset


def leer_rr(datos, offset):
    nombre, offset = leer_nombre(datos, offset)

    if offset + 10 > len(datos):
        raise ErrorDNS("cabecera de RR truncada")

    tipo, clase, ttl, rdlen = struct.unpack("!HHIH", datos[offset:offset + 10])
    offset += 10
    fin = offset + rdlen

    if fin > len(datos):
        raise ErrorDNS("rdata truncado")

    if tipo == 1 and rdlen == 4:
        valor = socket.inet_ntoa(datos[offset:fin])
    elif tipo == 28 and rdlen == 16:
        valor = socket.inet_ntop(socket.AF_INET6, datos[offset:fin])
    elif tipo in (2, 5, 12):
        valor, _ = leer_nombre(datos, offset)
    elif tipo == 6:
        mname, p = leer_nombre(datos, offset)
        rname, p = leer_nombre(datos, p)
        if p + 20 > fin:
            raise ErrorDNS("SOA truncado")
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", datos[p:p + 20])
        valor = (f"{mname} {rname} serial={serial} refresh={refresh} "
                 f"retry={retry} expire={expire} minimum={minimum}")
    elif tipo == 15 and rdlen >= 3:
        preferencia = struct.unpack("!H", datos[offset:offset + 2])[0]
        intercambio, _ = leer_nombre(datos, offset + 2)
        valor = f"{preferencia} {intercambio}"
    elif tipo == 16:
        partes = []
        p = offset
        while p < fin:
            n = datos[p]
            p += 1
            partes.append(datos[p:p + n].decode("utf-8", "replace"))
            p += n
        valor = '"' + '" "'.join(partes) + '"'
    else:
        valor = datos[offset:fin].hex()

    return {
        "nombre": nombre,
        "tipo": tipo,
        "clase": clase,
        "ttl": ttl,
        "valor": valor,
    }, fin


def leer_dns(datos):
    if len(datos) < 12:
        raise ErrorDNS("mensaje demasiado corto")

    ident, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", datos[:12])
    offset = 12

    preguntas = []
    for _ in range(qdcount):
        nombre, offset = leer_nombre(datos, offset)
        if offset + 4 > len(datos):
            raise ErrorDNS("pregunta truncada")
        tipo, clase = struct.unpack("!HH", datos[offset:offset + 4])
        offset += 4
        preguntas.append({"nombre": nombre, "tipo": tipo, "clase": clase})

    secciones = {}
    for clave, cantidad in (("respuesta", ancount),
                            ("autoridad", nscount),
                            ("adicional", arcount)):
        registros = []
        for _ in range(cantidad):
            rr, offset = leer_rr(datos, offset)
            registros.append(rr)
        secciones[clave] = registros

    return {
        "id": ident,
        "respuesta": bool(flags & 0x8000),
        "rcode": flags & 0x000F,
        "preguntas": preguntas,
        "secciones": secciones,
    }


def leer_pcap(ruta):
    with open(ruta, "rb") as archivo:
        datos = archivo.read()

    if len(datos) < 24:
        raise ValueError("archivo pcap vacio o incompleto")

    magia = datos[:4]
    nano = False

    if magia == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magia == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magia == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magia == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    else:
        raise ValueError("formato pcap no reconocido")

    _, _, _, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", datos[:24])

    offset = 24
    paquetes = []

    while offset + 16 <= len(datos):
        ts_sec, ts_frac, incl_len, _ = struct.unpack(endian + "IIII",
                                                     datos[offset:offset + 16])
        offset += 16

        if offset + incl_len > len(datos):
            break

        frame = datos[offset:offset + incl_len]
        offset += incl_len

        if nano:
            microsegundos = ts_frac // 1000
        else:
            microsegundos = ts_frac

        paquetes.append((ts_sec + microsegundos / 1_000_000, frame, linktype))

    return paquetes, snaplen


def extraer_payload(frame, linktype):
    if linktype == 1:
        if len(frame) < 14 or frame[12:14] != b"\x08\x00":
            return None
        ip = frame[14:]
    elif linktype in (101, 228):
        ip = frame
    else:
        return None

    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None

    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return None

    protocolo = ip[9]
    origen = socket.inet_ntoa(ip[12:16])
    destino = socket.inet_ntoa(ip[16:20])
    l4 = ip[ihl:]

    if protocolo == 17:
        if len(l4) < 8:
            return None
        sport, dport = struct.unpack("!HH", l4[:4])
        payload = l4[8:]
    elif protocolo == 6:
        if len(l4) < 20:
            return None
        sport, dport = struct.unpack("!HH", l4[:4])
        doff = (l4[12] >> 4) * 4
        if doff < 20 or len(l4) < doff + 2:
            return None
        largo = struct.unpack("!H", l4[doff:doff + 2])[0]
        payload = l4[doff + 2:doff + 2 + largo]
    else:
        return None

    if 53 not in (sport, dport):
        return None

    return origen, destino, sport, dport, payload


def nombre_tipo(tipo):
    return TIPOS.get(tipo, str(tipo))


def texto_rr(rr):
    return f"{rr['nombre']:<30} {rr['ttl']:>7} {nombre_tipo(rr['tipo']):<6} {rr['valor']}"


def main():
    if len(sys.argv) < 2:
        print("uso: dns_analyze.py <traza.pcap>", file=sys.stderr)
        return 1

    ruta = sys.argv[1]
    paquetes_crudos, _ = leer_pcap(ruta)

    paquetes = []
    for ts, frame, linktype in paquetes_crudos:
        extraido = extraer_payload(frame, linktype)
        if not extraido:
            continue
        origen, destino, sport, dport, payload = extraido
        try:
            dns = leer_dns(payload)
        except ErrorDNS:
            continue
        paquetes.append({
            "ts": ts,
            "origen": origen,
            "destino": destino,
            "sport": sport,
            "dport": dport,
            "dns": dns,
        })

    if not paquetes:
        print(f"No se encontraron mensajes DNS en {ruta}")
        return 1

    consultas = sum(1 for p in paquetes if not p["dns"]["respuesta"])
    respuestas = len(paquetes) - consultas

    print(f"Traza: {ruta}")
    print(f"Paquetes DNS: {len(paquetes)} ({consultas} consultas, {respuestas} respuestas)")
    print()
    print("===== Linea de tiempo =====")

    for i, paquete in enumerate(paquetes, 1):
        dns = paquete["dns"]
        hora = time.strftime("%H:%M:%S", time.localtime(paquete["ts"]))
        hora += f".{int((paquete['ts'] % 1) * 1_000_000):06d}"
        clase = "RESPUESTA" if dns["respuesta"] else "CONSULTA"

        print(f"{i:03d} {hora} {paquete['origen']}:{paquete['sport']} -> "
              f"{paquete['destino']}:{paquete['dport']}  {clase}")

        if dns["preguntas"]:
            pregunta = dns["preguntas"][0]
            linea = f"    Pregunta: {pregunta['nombre']} {nombre_tipo(pregunta['tipo'])}"
            if dns["respuesta"]:
                linea += f"  rcode={CODIGOS.get(dns['rcode'], dns['rcode'])}"
            print(linea)

        for seccion in ("respuesta", "autoridad", "adicional"):
            for rr in dns["secciones"][seccion]:
                if rr["tipo"] == 41:
                    continue
                print(f"    {seccion.capitalize():<11} {texto_rr(rr)}")

        print()

    resumen = {}
    for paquete in paquetes:
        dns = paquete["dns"]
        if not dns["preguntas"]:
            continue
        dominio = dns["preguntas"][0]["nombre"]
        grupo = resumen.setdefault(dominio, {"registros": {}, "tipos": set()})

        for seccion in ("respuesta", "autoridad", "adicional"):
            for rr in dns["secciones"][seccion]:
                if rr["tipo"] == 41:
                    continue
                clave = (rr["nombre"], rr["tipo"], rr["valor"])
                grupo["registros"][clave] = rr
                grupo["tipos"].add(nombre_tipo(rr["tipo"]))

    print("===== Resumen por dominio =====")
    for dominio, grupo in resumen.items():
        print()
        print(f"[{dominio}]")

        if not grupo["registros"]:
            print("  (sin registros en la respuesta)")
            continue

        ordenados = sorted(
            grupo["registros"].values(),
            key=lambda rr: (ORDEN_TIPOS.get(nombre_tipo(rr["tipo"]), 99),
                            rr["nombre"], rr["valor"]),
        )
        for rr in ordenados:
            print(f"  {texto_rr(rr)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
