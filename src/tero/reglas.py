"""Motor de reglas determinista para marcar hallazgos sobre un informe de Ghidra.

Las reglas se declaran en YAML con esta forma mínima::

    - id: TERO-IMP-001
      titulo: "Usa API de red Winsock"
      severidad: media
      criterios:
        imports:
          incluye: [ws2_32.dll::send, ws2_32.dll::recv]

    - id: TERO-STR-001
      titulo: "Posible URL en strings"
      severidad: media
      criterios:
        strings_regex: '^https?://'

Las severidades posibles son: info, baja, media, alta.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

SEVERIDADES = ("info", "baja", "media", "alta")


@dataclass(frozen=True)
class Hallazgo:
    regla_id: str
    titulo: str
    severidad: str
    evidencia: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "regla_id": self.regla_id,
            "titulo": self.titulo,
            "severidad": self.severidad,
            "evidencia": list(self.evidencia),
        }


def _imports_planos(informe: dict) -> list[str]:
    out = []
    for lib, funcs in (informe.get("imports") or {}).items():
        for f in funcs:
            out.append(f"{lib}::{f}")
    return sorted(out)


def _strings(informe: dict) -> list[tuple[str, str]]:
    return [(s["addr"], s["valor"]) for s in informe.get("strings") or []]


def _criterio_imports(c: dict, informe: dict) -> list[str]:
    planos = {i.lower() for i in _imports_planos(informe)}
    incluye = [x.lower() for x in c.get("incluye", [])]
    encontrados = [x for x in incluye if x in planos]
    if c.get("modo", "cualquiera") == "todos":
        if len(encontrados) == len(incluye):
            return encontrados
        return []
    return encontrados


def _criterio_strings_regex(c: str, informe: dict) -> list[str]:
    pat = re.compile(c)
    return [f"{addr}: {val}" for addr, val in _strings(informe) if pat.search(val)]


def _criterio_funcion_llama(c: Iterable[str], informe: dict) -> list[str]:
    objetivos = {x.lower() for x in c}
    hits = []
    for f in informe.get("funciones") or []:
        llamadas = {x.lower() for x in f.get("llama_a") or []}
        comunes = objetivos & llamadas
        if comunes:
            hits.append(f"{f['nombre']}@{f['entry']} -> {sorted(comunes)}")
    return hits


def evaluar(informe: dict, reglas: list[dict]) -> list[Hallazgo]:
    """Aplica cada regla y devuelve los hallazgos ordenados por severidad y id."""
    hallazgos: list[Hallazgo] = []
    for r in reglas:
        rid = r["id"]
        titulo = r["titulo"]
        sev = r.get("severidad", "info")
        if sev not in SEVERIDADES:
            raise ValueError(f"severidad invalida en {rid}: {sev}")
        criterios: dict[str, Any] = r.get("criterios", {})
        evidencia: list[str] = []
        for clave, valor in criterios.items():
            if clave == "imports":
                evidencia += _criterio_imports(valor, informe)
            elif clave == "strings_regex":
                evidencia += _criterio_strings_regex(valor, informe)
            elif clave == "funcion_llama":
                evidencia += _criterio_funcion_llama(valor, informe)
            else:
                raise ValueError(f"criterio desconocido en {rid}: {clave}")
        if evidencia:
            hallazgos.append(
                Hallazgo(rid, titulo, sev, tuple(sorted(set(evidencia))))
            )
    orden = {s: i for i, s in enumerate(reversed(SEVERIDADES))}
    hallazgos.sort(key=lambda h: (orden[h.severidad], h.regla_id))
    return hallazgos


def cargar_reglas(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        datos = yaml.safe_load(fh) or []
    if not isinstance(datos, list):
        raise ValueError(f"{path}: se esperaba una lista de reglas")
    return datos
