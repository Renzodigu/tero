#!/usr/bin/env python3
"""Keygen para yarara.exe, derivado del algoritmo recuperado con Tero.

Formato: YRR-AAAA-BBBB-CCCC
    A: aleatorio en [0x1000, 0x7FFF] con bit 12 = 1
    B: permutación de A por la tabla T recuperada del binario
    C: CRC-16/CCITT (0x1021, init 0xFFFF) sobre "YRR"+A+B en ASCII
"""
from __future__ import annotations

import random
import sys

T = [7, 12, 3, 10, 0, 14, 5, 9, 15, 2, 11, 6, 1, 13, 4, 8]


def permutar(x: int) -> int:
    y = 0
    for i in range(16):
        if x & (1 << i):
            y |= 1 << T[i]
    return y & 0xFFFF


def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def generar(a: int | None = None) -> str:
    if a is None:
        a = random.randint(0x1000, 0x7FFF) | 0x1000
    if not (0x1000 <= a <= 0x7FFF) or (a & 0x1000) == 0:
        raise ValueError("A fuera de rango o sin bit 12")
    b = permutar(a)
    base = f"YRR{a:04X}{b:04X}".encode("ascii")
    c = crc16_ccitt(base)
    return f"YRR-{a:04X}-{b:04X}-{c:04X}"


if __name__ == "__main__":
    a = int(sys.argv[1], 16) if len(sys.argv) == 2 else None
    print(generar(a))
