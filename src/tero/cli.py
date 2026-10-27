"""CLI de Tero.

Comandos::

    tero analyze <binario> --out out/
        Corre Ghidra sobre el binario y genera informe + hallazgos.

    tero reglas <informe.json>
        Vuelve a correr solo las reglas sobre un informe ya generado.

    tero demo
        Compila (si falta) y analiza los crackmes del repo (carpincho + yarara).
"""

from __future__ import annotations

import argparse
import importlib.resources as resources
import json
import os
import subprocess
import sys
from pathlib import Path

from . import ghidra, reglas, informe


RAIZ_REPO = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = RAIZ_REPO / "ghidra_scripts"
MUESTRAS = RAIZ_REPO / "muestras"
REPORTES = RAIZ_REPO / "reportes"


def _reglas_default() -> list[dict]:
    with resources.files("tero.rules").joinpath("base.yaml").open(encoding="utf-8") as fh:
        import yaml

        return yaml.safe_load(fh)


def _resumen(datos: dict, hallazgos) -> dict:
    por = {}
    for h in hallazgos:
        por[h.severidad] = por.get(h.severidad, 0) + 1
    return {
        "funciones": len(datos.get("funciones") or []),
        "strings": len(datos.get("strings") or []),
        "imports": sum(len(v) for v in (datos.get("imports") or {}).values()),
        "hallazgos": len(hallazgos),
        "por_severidad": por,
    }


def cmd_analyze(args) -> int:
    binario = Path(args.binario).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    informe_json = out / f"{binario.stem}.json"
    proyecto = out / "ghidra_project"

    inst = ghidra.localizar(args.ghidra)
    print(f"[tero] usando Ghidra en {inst.raiz}", file=sys.stderr)
    print(f"[tero] analizando {binario.name} ...", file=sys.stderr)
    ghidra.analizar(
        binario,
        informe_json,
        proyecto,
        scripts_dir=SCRIPTS_DIR,
        instalacion=inst,
        timeout_s=args.timeout,
        verbose=args.verbose,
    )
    datos = ghidra.leer_informe(informe_json)
    rs = _reglas_default()
    hallazgos = reglas.evaluar(datos, rs)
    resumen = _resumen(datos, hallazgos)
    md = informe.to_markdown(datos["programa"], hallazgos, resumen)
    informe.escribir(out / f"{binario.stem}.md", md)
    (out / f"{binario.stem}.hallazgos.json").write_text(
        json.dumps([h.to_dict() for h in hallazgos], indent=2), encoding="utf-8"
    )
    print(
        f"[tero] OK: {len(hallazgos)} hallazgos. "
        f"Informe: {out / (binario.stem + '.md')}",
        file=sys.stderr,
    )
    return 0


def cmd_reglas(args) -> int:
    datos = ghidra.leer_informe(Path(args.informe))
    rs = _reglas_default()
    hallazgos = reglas.evaluar(datos, rs)
    out = [h.to_dict() for h in hallazgos]
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


def cmd_demo(args) -> int:
    # Compila si faltan
    bin_dir = MUESTRAS / "bin"
    for nombre in ("carpincho", "yarara"):
        exe = bin_dir / f"{nombre}.exe"
        if not exe.exists():
            bin_dir.mkdir(exist_ok=True)
            print(f"[tero] compilando {nombre}.c ...", file=sys.stderr)
            subprocess.check_call(
                [
                    "gcc",
                    "-O2",
                    "-s",
                    "-static",
                    "-Wall",
                    "-Wextra",
                    "-o",
                    str(exe),
                    str(MUESTRAS / "src" / f"{nombre}.c"),
                ]
            )
    rc = 0
    for nombre in ("carpincho", "yarara"):
        a = argparse.Namespace(
            binario=str(bin_dir / f"{nombre}.exe"),
            out=str(REPORTES / nombre),
            ghidra=args.ghidra,
            timeout=args.timeout,
            verbose=args.verbose,
        )
        rc |= cmd_analyze(a)
    return rc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tero")
    p.add_argument("--ghidra", help="ruta a GHIDRA_INSTALL_DIR", default=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analiza un binario")
    a.add_argument("binario")
    a.add_argument("--out", default="out/")
    a.add_argument("--timeout", type=int, default=300)
    a.add_argument("--verbose", action="store_true")
    a.set_defaults(func=cmd_analyze)

    r = sub.add_parser("reglas", help="re-evalua reglas sobre un informe JSON")
    r.add_argument("informe")
    r.set_defaults(func=cmd_reglas, timeout=0, verbose=False)

    d = sub.add_parser("demo", help="analiza los crackmes del repo")
    d.add_argument("--timeout", type=int, default=300)
    d.add_argument("--verbose", action="store_true")
    d.set_defaults(func=cmd_demo)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
