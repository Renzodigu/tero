# Tero

**Pipeline determinista de reverse engineering sobre Ghidra: binario → informe estructurado → hallazgos por reglas, con revisión opcional de Claude.**

Tero toma un ejecutable, lo abre con Ghidra 12.1 vía [pyghidra](https://pypi.org/project/pyghidra/) (sin GUI), extrae un informe estructurado (imports, exports, strings, pseudocódigo de cada función) y evalúa reglas en YAML sobre ese informe para producir hallazgos trazables al archivo. Los dos crackmes del repo (`carpincho`, `yarara`) sirven de demo end-to-end.

> *Tero* es el pájaro centinela de la pampa: avisa antes de que uno vea nada.

![CI](https://github.com/Renzodigu/tero/actions/workflows/ci.yml/badge.svg)

## Por qué otra herramienta de RE

Las demos "AI para malware" le pasan el pseudocódigo entero a un modelo y le piden conclusiones. Para un analista eso es poco auditable y caro de rehacer. Tero separa dos cosas:

- **El trabajo que no necesita IA** — abrir el binario, decompilar, listar imports/strings/funciones, marcar patrones conocidos (antidebug, red, registro, resolución dinámica de APIs, URLs embebidas) — se hace con Ghidra + reglas deterministas que corren offline en segundos.
- **El trabajo que sí la aprovecha** — contextualizar una función específica, explicar un algoritmo recuperado — queda como paso opcional, con el pseudocódigo ya acotado.

Las reglas producen hallazgos con `regla_id`, severidad y la lista exacta de evidencia (`ws2_32.dll::socket`, `FUN_140002ce5@0x140002ce5 -> ['strncmp']`, etc.), así que dos corridas sobre el mismo binario dan el mismo informe.

## Qué hay en el repo

```
tero/
├── src/tero/            # paquete Python (CLI, pyghidra, reglas, informe)
│   └── rules/base.yaml  # reglas base: red, registro, cripto, antidebug, strings
├── muestras/
│   ├── src/             # dos crackmes en C (carpincho, yarara)
│   └── keygen_*.py      # keygens recuperados por el analista
├── ghidra_scripts/      # script Jython opcional (equivalente al módulo pyghidra)
├── tests/               # tests determinísticos del motor de reglas y los keygens
├── docs/writeups/       # análisis paso a paso de los dos crackmes
└── reportes/            # salida de `tero demo` (ignorada en git)
```

## Instalación

Requisitos: **Python 3.11+**, **JDK 21** (Microsoft Build o Temurin), **Ghidra 12.1.4** y, opcional pero útil para rearmar los crackmes, un **GCC** (MinGW-w64 en Windows).

```bash
# 1. Descargar Ghidra 12.1.4 del release oficial de la NSA
#    https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build
#    y descomprimirlo. Exportar la raíz:
export GHIDRA_INSTALL_DIR=/ruta/a/ghidra_12.1.4_PUBLIC

# 2. Instalar Tero y sus dependencias (incluye pyghidra)
pip install -e ".[dev]"
pip install pyghidra
```

Para rearmar los crackmes:

```bash
cd muestras && make        # o `mingw32-make` en Windows
```

## Uso

```bash
# Analizar un binario y escribir informe + hallazgos
tero analyze path/al/binario.exe --out reportes/binario/

# Correr los dos crackmes del repo de punta a punta
tero demo

# Re-evaluar las reglas sobre un informe ya generado (sin volver a correr Ghidra)
tero reglas reportes/carpincho/carpincho.json
```

Cada corrida genera tres archivos en `--out`:

- `<nombre>.json` — el informe estructurado completo (programa, imports, exports, strings, funciones con pseudocódigo).
- `<nombre>.hallazgos.json` — la lista de hallazgos ordenada por severidad.
- `<nombre>.md` — informe Markdown listo para pegar en un ticket o un writeup.

## Reglas

Cada regla es un objeto YAML con `id`, `titulo`, `severidad` (`info|baja|media|alta`) y `criterios`. Los criterios soportados hoy son:

| Criterio | Qué chequea |
|---|---|
| `imports.incluye` | Pares `dll::función` presentes. `modo: todos` exige todos; `cualquiera` (default) basta con uno. |
| `strings_regex` | Expresión regular contra la lista de strings definidos. |
| `funcion_llama` | Alguna función no-library llama a *una* de estas funciones. Útil para detectar validadores de licencia (`strcmp`, `memcmp`). |

Se pueden combinar criterios dentro de una misma regla; una regla dispara cuando *todos* sus criterios aportan evidencia. Ver `src/tero/rules/base.yaml` para los nueve patrones que vienen de fábrica.

## Demo: los dos crackmes

Los dos ejecutables son **inofensivos**: solo leen stdin y comparan contra un algoritmo embebido. Están pensados para que el analista los decompile con Tero y recupere el algoritmo. Los writeups están en `docs/writeups/`.

| Binario | Qué esconde | Hallazgos de Tero |
|---|---|---|
| `carpincho.exe` | Validador de serial con FNV-1a + rotación XOR | Resolución dinámica de APIs (CRT estática), función comparadora con `strncmp` |
| `yarara.exe` | Licencia con permutación de bits + CRC-16/CCITT | Resolución dinámica de APIs, función comparadora con `memcmp` |

Cada uno trae su keygen en `muestras/keygen_<nombre>.py`. Los tests de `tests/test_keygens.py` validan automáticamente que los seriales generados son aceptados por el crackme.

## Tests

```bash
pytest -q
```

Los tests están divididos en:

- `test_reglas.py` — motor de reglas (no requiere Ghidra ni los binarios).
- `test_keygens.py` — valida los keygens contra los crackmes compilados; se saltean si falta el binario.

## Qué está fuera de alcance (hoy)

- Debuggers / análisis dinámico — Tero es puramente estático sobre decompilado.
- Formatos no-PE/ELF — Ghidra abre muchos más (Mach-O, APK, firmware), pero las reglas base están orientadas a PE de Windows.
- Red o C2 reales — el pipeline no toca Internet.

## Licencia

MIT. Ver `LICENSE`.
