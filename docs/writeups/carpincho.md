# Writeup: `carpincho.exe`

Objetivo: recuperar el algoritmo de validación de serial sin ver el código fuente, y escribir un keygen.

## 1. Reconocimiento con Tero

```bash
tero analyze muestras/bin/carpincho.exe --out reportes/carpincho/
```

El informe (`reportes/carpincho/carpincho.md`) marca dos cosas:

- **TERO-IMP-DYN-001** — el binario resuelve APIs con `LoadLibraryA`/`GetProcAddress`. Esto es la *CRT* estática de MinGW, no un rasgo del crackme.
- **TERO-FUN-LICENCIA-001** — hay una función no-library que llama a `strncmp`: `FUN_140002ce5@0x140002ce5`. Ese es nuestro candidato.

Los strings decompilados confirman la hipótesis: `"CRP-"`, `"Licencia valida. Gracias por su compra."`, `"Licencia invalida."`, `"== Carpincho Soft v1.0 =="`.

## 2. Función `FUN_140002ce5`

El pseudocódigo (recortado) muestra:

```c
if (strlen(nombre) < 3 || strlen(serial) != 13) return 0;
if (strncmp(serial, "CRP-", 4) != 0 || serial[8] != '-') return 0;
// hex4(serial+4, &a); hex4(serial+9, &b);
// return a == hash_nombre(nombre) && b == bloque_control(a);
```

Mirando `hash_nombre`:

```c
h = 0x811C9DC5;
for (p = nombre; *p; p++) {
    h ^= *p;
    h *= 0x01000193;
}
return (h ^ (h >> 16)) & 0xFFFF;
```

Los dos "números mágicos" (`0x811C9DC5` offset y `0x01000193` multiplier) son la firma de **FNV-1a 32-bit**, plegado a 16 bits.

Y `bloque_control`:

```c
return (rotl16(a, 5)) ^ 0xCAFE;
```

## 3. Keygen

Con eso, el keygen es directo:

```python
A = fnv1a_16(nombre)
B = rol16(A, 5) ^ 0xCAFE
serial = f"CRP-{A:04X}-{B:04X}"
```

Ver [`muestras/keygen_carpincho.py`](../../muestras/keygen_carpincho.py). El test `test_keygen_carpincho_valida_en_el_crackme` genera seriales para varios usuarios y los pasa por el binario; todos vuelven con `Licencia valida`.

## 4. Lecciones

- Las constantes son el camino más corto a identificar algoritmos conocidos. FNV, CRC, MD5, AES tienen firmas numéricas inconfundibles.
- Las reglas de Tero no "resuelven" el crackme — señalan en 10 segundos dónde mirar.
- La CRT estática ensucia los hallazgos de APIs dinámicas; es ruido esperable en binarios de MinGW.
