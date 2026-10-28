"""Puente con Ghidra vía pyghidra (sin subprocess).

Mantiene la misma superficie pública que la versión anterior:

- ``localizar(ghidra_dir)`` para encontrar la instalación.
- ``analizar(binario, salida_json, proyecto_dir, ...)`` para producir el informe
  JSON determinista que Tero consume.
- ``leer_informe(ruta)`` como shortcut de ``json.load``.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

MAX_FUNCIONES = 60


class GhidraNoEncontrado(RuntimeError):
    pass


@dataclass
class Instalacion:
    raiz: Path


def localizar(ghidra_dir: str | os.PathLike | None = None) -> Instalacion:
    """Devuelve la instalación de Ghidra, mirando (en orden):

    1. El argumento ``ghidra_dir``.
    2. La variable de entorno ``GHIDRA_INSTALL_DIR``.
    3. El binario ``analyzeHeadless`` en PATH.
    """
    candidatas: list[Path] = []
    if ghidra_dir:
        candidatas.append(Path(ghidra_dir))
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        candidatas.append(Path(env))
    exe = shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat")
    if exe:
        candidatas.append(Path(exe).resolve().parent.parent)
    for c in candidatas:
        if (c / "support").is_dir() and (c / "Ghidra" / "application.properties").exists():
            return Instalacion(c)
    raise GhidraNoEncontrado(
        "No encuentro Ghidra. Pasá --ghidra <ruta> o exportá GHIDRA_INSTALL_DIR."
    )


def _addr_hex(addr) -> str:
    return f"0x{addr.getOffset():x}"


def _program_meta(p) -> dict:
    desc = p.getLanguage().getLanguageDescription()
    return {
        "nombre": p.getName(),
        "arquitectura": f"{desc.getProcessor()}:{desc.getSize()}:{desc.getEndian()}",
        "compilador": str(p.getCompilerSpec().getCompilerSpecID()),
        "image_base": _addr_hex(p.getImageBase()),
        "md5": p.getExecutableMD5(),
        "sha256": p.getExecutableSHA256(),
    }


def _listar_imports(p) -> dict[str, list[str]]:
    sm = p.getSymbolTable()
    out: dict[str, list[str]] = {}
    it = sm.getExternalSymbols()
    while it.hasNext():
        s = it.next()
        parent = s.getParentNamespace()
        lib = parent.getName() if parent is not None else "?"
        out.setdefault(lib, []).append(s.getName())
    return {k: sorted(set(v)) for k, v in out.items()}


def _listar_exports(p) -> list[dict]:
    sm = p.getSymbolTable()
    it = sm.getExternalEntryPointIterator()
    out = []
    while it.hasNext():
        addr = it.next()
        sym = sm.getPrimarySymbol(addr)
        if sym is not None:
            out.append({"nombre": sym.getName(), "addr": _addr_hex(addr)})
    return out


def _listar_strings(p, minimo: int = 4) -> list[dict]:
    out = []
    it = p.getListing().getDefinedData(True)
    while it.hasNext():
        d = it.next()
        if not d.hasStringValue():
            continue
        v = d.getValue()
        if v is None:
            continue
        s = str(v)
        if len(s) < minimo:
            continue
        out.append({"addr": _addr_hex(d.getAddress()), "valor": s})
    return out


def _funciones(p, limite: int = MAX_FUNCIONES) -> list[dict]:
    """Decompila hasta ``limite`` funciones propias (sin contar externas ni thunks)."""
    from ghidra.app.decompiler import DecompileOptions, DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(p)
    out = []
    for f in p.getFunctionManager().getFunctions(True):
        if f.isExternal() or f.isThunk():
            continue
        if len(out) >= limite:
            break
        llamadas = sorted({c.getName() for c in f.getCalledFunctions(monitor)})
        res = ifc.decompileFunction(f, 30, monitor)
        decomp = res.getDecompiledFunction()
        texto = decomp.getC() if decomp else ""
        out.append({
            "nombre": f.getName(),
            "entry": _addr_hex(f.getEntryPoint()),
            "tamanio": int(f.getBody().getNumAddresses()),
            "llama_a": llamadas,
            "pseudocodigo": texto,
        })
    return out


def analizar(
    binario: Path,
    salida_json: Path,
    proyecto_dir: Path,
    *,
    scripts_dir: Path | None = None,  # kept for CLI compat; no se usa
    instalacion: Instalacion | None = None,
    timeout_s: int = 300,
    verbose: bool = False,
    max_funciones: int = MAX_FUNCIONES,
) -> Path:
    """Analiza ``binario`` con pyghidra y escribe el informe en ``salida_json``."""
    import pyghidra

    inst = instalacion or localizar()
    proyecto_dir.mkdir(parents=True, exist_ok=True)
    salida_json.parent.mkdir(parents=True, exist_ok=True)

    pyghidra.start(verbose=verbose, install_dir=inst.raiz)
    with pyghidra.open_program(
        binary_path=binario,
        project_location=proyecto_dir,
        project_name="tero",
        analyze=True,
    ) as flat_api:
        p = flat_api.getCurrentProgram()
        informe = {
            "programa": _program_meta(p),
            "imports": _listar_imports(p),
            "exports": _listar_exports(p),
            "strings": _listar_strings(p),
            "funciones": _funciones(p, max_funciones),
        }
    salida_json.write_text(json.dumps(informe, indent=2, sort_keys=True), encoding="utf-8")
    return salida_json


def leer_informe(ruta: Path) -> dict:
    with open(ruta, encoding="utf-8") as fh:
        return json.load(fh)
