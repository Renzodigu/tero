"""Tests determinìsticos del motor de reglas de Tero.

Cubren:
- un informe mínimo que dispara reglas de imports, strings y funcion_llama;
- la ordenación por severidad;
- el modo "todos" vs. "cualquiera";
- errores de severidad y criterio desconocido.
"""

from __future__ import annotations

import pytest

from tero import reglas


INFORME = {
    "programa": {"nombre": "x.exe"},
    "imports": {
        "ws2_32.dll": ["WSAStartup", "socket"],
        "kernel32.dll": ["GetProcAddress", "LoadLibraryA", "IsDebuggerPresent"],
    },
    "strings": [
        {"addr": "0x1", "valor": "http://ejemplo.invalid/x"},
        {"addr": "0x2", "valor": "hola"},
    ],
    "funciones": [
        {"nombre": "FUN_1000", "entry": "0x1000", "llama_a": ["strcmp"]},
        {"nombre": "FUN_2000", "entry": "0x2000", "llama_a": ["printf"]},
    ],
}


def _reglas_demo():
    return [
        {
            "id": "A",
            "titulo": "winsock",
            "severidad": "media",
            "criterios": {"imports": {"incluye": ["ws2_32.dll::socket"]}},
        },
        {
            "id": "B",
            "titulo": "resolucion dinamica",
            "severidad": "alta",
            "criterios": {
                "imports": {
                    "incluye": ["kernel32.dll::GetProcAddress", "kernel32.dll::LoadLibraryA"],
                    "modo": "todos",
                }
            },
        },
        {
            "id": "C",
            "titulo": "url embebida",
            "severidad": "media",
            "criterios": {"strings_regex": "^https?://"},
        },
        {
            "id": "D",
            "titulo": "validador",
            "severidad": "info",
            "criterios": {"funcion_llama": ["strcmp"]},
        },
    ]


def test_evaluar_dispara_todas():
    hs = reglas.evaluar(INFORME, _reglas_demo())
    ids = [h.regla_id for h in hs]
    assert ids == ["B", "A", "C", "D"]  # orden por severidad desc + id asc


def test_modo_todos_exige_todos_los_imports():
    r = [
        {
            "id": "X",
            "titulo": "ambos",
            "severidad": "media",
            "criterios": {
                "imports": {
                    "incluye": ["kernel32.dll::GetProcAddress", "nope.dll::nada"],
                    "modo": "todos",
                }
            },
        }
    ]
    assert reglas.evaluar(INFORME, r) == []


def test_strings_regex_lista_evidencia():
    r = [
        {
            "id": "S",
            "titulo": "url",
            "severidad": "media",
            "criterios": {"strings_regex": "^https?://"},
        }
    ]
    out = reglas.evaluar(INFORME, r)
    assert len(out) == 1
    assert "ejemplo.invalid" in out[0].evidencia[0]


def test_severidad_invalida():
    with pytest.raises(ValueError):
        reglas.evaluar(INFORME, [{"id": "Z", "titulo": "x", "severidad": "critica", "criterios": {}}])


def test_criterio_desconocido():
    with pytest.raises(ValueError):
        reglas.evaluar(
            INFORME,
            [{"id": "Z", "titulo": "x", "severidad": "baja", "criterios": {"ovnis": True}}],
        )


def test_reglas_default_cargan():
    from pathlib import Path

    rs = reglas.cargar_reglas(Path("src/tero/rules/base.yaml"))
    assert isinstance(rs, list) and rs
    assert all({"id", "titulo", "severidad", "criterios"} <= set(r) for r in rs)
