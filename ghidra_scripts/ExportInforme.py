# @category Tero
# @author Renzo Di Guglielmo
# Exporta un informe JSON del binario analizado para que Tero lo lea.
#
# Compatible con el interprete Jython 2.7 que Ghidra usa por default.
# No usa f-strings ni type hints.

import json

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor


def _addr_hex(addr):
    return "0x%x" % addr.getOffset()


def program_meta(p):
    desc = p.getLanguage().getLanguageDescription()
    return {
        "nombre": p.getName(),
        "arquitectura": "%s:%s:%s" % (desc.getProcessor(), desc.getSize(), desc.getEndian()),
        "compilador": str(p.getCompilerSpec().getCompilerSpecID()),
        "image_base": _addr_hex(p.getImageBase()),
        "md5": p.getExecutableMD5(),
        "sha256": p.getExecutableSHA256(),
    }


def listar_imports(p):
    sm = p.getSymbolTable()
    out = {}
    it = sm.getExternalSymbols()
    while it.hasNext():
        s = it.next()
        parent = s.getParentNamespace()
        lib = parent.getName() if parent is not None else "?"
        out.setdefault(lib, []).append(s.getName())
    for k in out:
        out[k] = sorted(set(out[k]))
    return out


def listar_exports(p):
    sm = p.getSymbolTable()
    it = sm.getExternalEntryPointIterator()
    out = []
    while it.hasNext():
        addr = it.next()
        sym = sm.getPrimarySymbol(addr)
        if sym is not None:
            out.append({"nombre": sym.getName(), "addr": _addr_hex(addr)})
    return out


def listar_strings(p, minimo=4):
    out = []
    listing = p.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        if not d.hasStringValue():
            continue
        v = d.getValue()
        if v is None:
            continue
        s = unicode(v)
        if len(s) < minimo:
            continue
        out.append({"addr": _addr_hex(d.getAddress()), "valor": s})
    return out


def funciones_y_decompilado(p, limite_funcs=60):
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(p)
    funcs = []
    fm = p.getFunctionManager()
    todas = fm.getFunctions(True)
    contador = 0
    for f in todas:
        if f.isExternal() or f.isThunk():
            continue
        if contador >= limite_funcs:
            break
        contador += 1
        llamadas = sorted(set([c.getName() for c in f.getCalledFunctions(monitor)]))
        res = ifc.decompileFunction(f, 30, monitor)
        c = res.getDecompiledFunction()
        texto = c.getC() if c else ""
        funcs.append({
            "nombre": f.getName(),
            "entry": _addr_hex(f.getEntryPoint()),
            "tamanio": int(f.getBody().getNumAddresses()),
            "llama_a": llamadas,
            "pseudocodigo": texto,
        })
    return funcs


def main():
    args = getScriptArgs()  # Ghidra lo expone en el namespace del script
    if not args:
        print("Uso: ExportInforme.py <ruta_salida.json>")
        return
    salida = args[0]
    p = currentProgram  # idem
    informe = {
        "programa": program_meta(p),
        "imports": listar_imports(p),
        "exports": listar_exports(p),
        "strings": listar_strings(p),
        "funciones": funciones_y_decompilado(p),
    }
    fh = open(salida, "w")
    try:
        fh.write(json.dumps(informe, indent=2, sort_keys=True))
    finally:
        fh.close()
    print("Informe escrito en %s" % salida)


main()
