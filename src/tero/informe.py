"""Renderizado del informe final (Markdown y HTML opcional)."""

from __future__ import annotations

import re
from pathlib import Path

from .reglas import Hallazgo

SEV_LABEL = {"alta": "🟥 alta", "media": "🟧 media", "baja": "🟨 baja", "info": "⬜ info"}


def _code(texto) -> str:
    """Span de código inline a prueba de backticks: los strings del binario los escribe su autor."""
    texto = " ".join(str(texto).split()) or " "
    fence = "`" * (max((len(r) for r in re.findall(r"`+", texto)), default=0) + 1)
    pad = " " if texto.startswith("`") or texto.endswith("`") else ""
    return f"{fence}{pad}{texto}{pad}{fence}"


def to_markdown(programa: dict, hallazgos: list[Hallazgo], resumen: dict) -> str:
    out = [f"# Tero — informe de {_code(programa['nombre'])}", ""]
    out.append("## Datos del binario")
    out.append("")
    out.append("| Campo | Valor |")
    out.append("|---|---|")
    for k in ("nombre", "arquitectura", "compilador", "image_base", "md5", "sha256"):
        out.append(f"| {k} | {_code(programa.get(k)).replace('|', chr(92) + '|')} |")
    out.append("")
    out.append("## Resumen")
    out.append("")
    out.append(
        f"- Funciones analizadas: **{resumen['funciones']}**  "
        f"\n- Strings con texto: **{resumen['strings']}**  "
        f"\n- Imports: **{resumen['imports']}** APIs externas  "
        f"\n- Hallazgos: **{resumen['hallazgos']}** "
        f"(alta: {resumen['por_severidad'].get('alta',0)}, "
        f"media: {resumen['por_severidad'].get('media',0)}, "
        f"baja: {resumen['por_severidad'].get('baja',0)}, "
        f"info: {resumen['por_severidad'].get('info',0)})"
    )
    out.append("")
    out.append("## Hallazgos")
    out.append("")
    if not hallazgos:
        out.append("_Sin hallazgos._")
    else:
        for h in hallazgos:
            out.append(f"### {h.regla_id} — {h.titulo}  ·  {SEV_LABEL[h.severidad]}")
            out.append("")
            for e in h.evidencia:
                out.append(f"- {_code(e)}")
            out.append("")
    return "\n".join(out) + "\n"


def escribir(path: Path, texto: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(texto, encoding="utf-8")
    return path
