# Tero

**Pipeline determinista de reverse engineering sobre Ghidra: binario → informe estructurado → hallazgos por reglas.**

Tero toma un ejecutable, lo abre con Ghidra 12.1 vía [pyghidra](https://pypi.org/project/pyghidra/) (sin GUI), extrae un informe estructurado (imports, exports, strings, pseudocódigo de cada función) y evalúa reglas en YAML sobre ese informe para producir hallazgos trazables al archivo. Los dos crackmes del repo (`carpincho`, `yarara`) sirven de demo end-to-end.

> *Tero* es el pájaro centinela de la pampa: avisa antes de que uno vea nada.

![CI](https://github.com/Renzodigu/tero/actions/workflows/ci.yml/badge.svg)

## Por qué otra herramienta de RE

Las demos "AI para malware" le pasan el pseudocódigo entero a un modelo y le piden conclusiones. Para un analista eso es poco auditable y caro de rehacer. Tero separa dos cosas:

- **El trabajo que no necesita IA** — abrir el binario, decompilar, listar imports/strings/funciones, marcar patrones conocidos (antidebug, red, registro, resolución dinámica de APIs, URLs embebidas) — se hace con Ghidra + reglas deterministas que corren offline en segundos.
- **El trabajo que sí podría aprovecharla** — contextualizar una función específica, explicar un algoritmo recuperado — queda para el analista, con el pseudocódigo ya acotado. Tero no llama a ningún modelo; una revisión opcional con IA sobre las funciones marcadas está en la hoja de ruta.

Las reglas producen hallazgos con `regla_id`, severidad y la lista exacta de evidencia (`ws2_32.dll::socket`, `FUN_140003460@0x140003460 -> ['strncmp']`, etc.), así que dos corridas sobre el mismo binario dan el mismo informe.

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
#    En Windows, para que quede guardada (PowerShell; vale para las terminales nuevas):
#    [Environment]::SetEnvironmentVariable('GHIDRA_INSTALL_DIR', 'C:\ruta\a\ghidra_12.1.4_PUBLIC', 'User')

# 2. Instalar Tero y pyghidra
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

# Decompilar más funciones propias (default: 60; externas y thunks no cuentan)
tero analyze path/al/binario.exe --out reportes/binario/ --max-funciones 300

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
| `funcion_llama` | Alguna función propia del binario (no importada) llama a *una* de estas funciones. Útil para encontrar validadores de licencia (`strcmp`, `memcmp`); también marca código de la CRT que compara strings, así que cada candidata hay que mirarla. |

Se pueden combinar criterios dentro de una misma regla; una regla dispara cuando *todos* sus criterios aportan evidencia (por ejemplo, `imports` de sockets **y** una URL en `strings_regex`), y el hallazgo junta la evidencia de todos. Ver `src/tero/rules/base.yaml` para los nueve patrones que vienen de fábrica.

## Demo: los dos crackmes

Los dos ejecutables son **inofensivos**: solo leen stdin y comparan contra un algoritmo embebido. Están pensados para que el analista los decompile con Tero y recupere el algoritmo. Los writeups están en `docs/writeups/`.

| Binario | Qué esconde | Hallazgos de Tero |
|---|---|---|
| `carpincho.exe` | Validador de serial con FNV-1a + rotación XOR | Resolución dinámica de APIs (CRT de MinGW) y dos funciones con `strncmp`: `main`, que es el validador, y una de la CRT |
| `yarara.exe` | Licencia con permutación de bits + CRC-16/CCITT-FALSE | Los mismos dos: el validador está en `main` y la otra función es de la CRT |

Así sale la parte de hallazgos de `reportes/yarara/yarara.md` (Ghidra 12.1.4, unos 30 segundos, 54 funciones propias decompiladas):

```markdown
### TERO-IMP-DYN-001 — Resolución dinámica de APIs con GetProcAddress  ·  🟧 media

- `kernel32.dll::getprocaddress`
- `kernel32.dll::loadlibrarya`

### TERO-FUN-LICENCIA-001 — Función comparadora de strings tipo validador de licencia  ·  ⬜ info

- `FUN_140002ce5@0x140002ce5 -> ['strncmp']`
- `FUN_140003460@0x140003460 -> ['strncmp']`
```

Los dos hallazgos tienen ruido a propósito, y los writeups explican cómo descartarlo: `LoadLibraryA`/`GetProcAddress` vienen del arranque de MinGW, y `FUN_140002ce5` es una función de la CRT que busca secciones del PE por nombre. El validador es `FUN_140003460` (`main`).

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
- Binarios grandes — se decompilan las primeras `--max-funciones` funciones propias en orden de dirección. En un binario con la CRT enlazada estáticamente, parte de ellas son de la biblioteca de C.
- IA — Tero no usa ningún modelo (ver la hoja de ruta).

## Hoja de ruta

- [ ] Informe HTML con la ficha del binario, los hallazgos y el pseudocódigo de cada función marcada
- [ ] Separar el código de arranque de la CRT para que no genere falsos positivos (hoy `TERO-IMP-DYN-001` y `TERO-FUN-LICENCIA-001` lo marcan en los crackmes)
- [ ] Más reglas y una muestra más realista que los crackmes
- [ ] README en inglés
- [ ] Revisión opcional con IA sobre las funciones que las reglas ya marcaron; nunca como parte del análisis base

## Licencia

MIT. Ver `LICENSE`.
