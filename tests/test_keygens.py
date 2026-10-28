"""Verifica que los keygens producen seriales válidos para los crackmes."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]
MUESTRAS = RAIZ / "muestras"
BIN = MUESTRAS / "bin"


def _reqs_crackmes():
    if not (BIN / "carpincho.exe").exists() or not (BIN / "yarara.exe").exists():
        pytest.skip("ejecutá `mingw32-make -C muestras` para compilar los crackmes")


def test_keygen_carpincho_valida_en_el_crackme():
    _reqs_crackmes()
    sys.path.insert(0, str(MUESTRAS))
    from keygen_carpincho import serial  # type: ignore

    # el crackme pide >=3 caracteres de usuario
    for nombre in ["renzo", "ANA", "pablo-arg", "xyz"]:
        s = serial(nombre)
        res = subprocess.run(
            [str(BIN / "carpincho.exe")],
            input=f"{nombre}\n{s}\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "Licencia valida" in res.stdout, (nombre, s, res.stdout)


def test_keygen_yarara_valida_en_el_crackme():
    _reqs_crackmes()
    sys.path.insert(0, str(MUESTRAS))
    from keygen_yarara import generar  # type: ignore

    for a in [0x1234, 0x1FFF, 0x7FFF, 0x1000]:
        lic = generar(a)
        res = subprocess.run(
            [str(BIN / "yarara.exe")],
            input=f"{lic}\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "OK" in res.stdout, (a, lic, res.stdout)
