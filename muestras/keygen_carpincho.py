#!/usr/bin/env python3
"""Keygen para carpincho.exe, derivado del algoritmo recuperado con Tero.

Uso:
    python keygen_carpincho.py <usuario>

El algoritmo (ver docs/writeups/carpincho.md) es:
    A = FNV-1a 32-bit del nombre, plegado a 16 bits (XOR mitades)
    B = rotar_izq_5(A) XOR 0xCAFE
    serial = f"CRP-{A:04X}-{B:04X}"
"""
from __future__ import annotations

import sys


def hash_nombre(nombre: str) -> int:
    h = 0x811C9DC5
    for b in nombre.encode("utf-8"):
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return (h ^ (h >> 16)) & 0xFFFF


def bloque_control(a: int) -> int:
    r = ((a << 5) | (a >> 11)) & 0xFFFF
    return r ^ 0xCAFE


def serial(nombre: str) -> str:
    a = hash_nombre(nombre)
    b = bloque_control(a)
    return f"CRP-{a:04X}-{b:04X}"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("uso: keygen_carpincho.py <usuario>", file=sys.stderr)
        sys.exit(2)
    print(serial(sys.argv[1]))
