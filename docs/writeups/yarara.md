# Writeup: `yarara.exe`

Más duro que `carpincho`: la licencia pasa por una tabla de permutación de bits y un checksum CRC-16/CCITT, y hay una restricción de rango.

## 1. Reconocimiento con Tero

```bash
tero analyze muestras/bin/yarara.exe --out reportes/yarara/
```

Hallazgos:

- **TERO-IMP-DYN-001** — resolución dinámica (CRT estática, ruido).
- **TERO-FUN-LICENCIA-001** — `FUN_140001...` llama a `memcmp`.

Strings relevantes: `"YRR-"`, `"== Yarara License v1.0 =="`, `"OK"`, `"Licencia invalida."`.

## 2. Formato y restricciones

El decompilado del validador muestra:

```c
if (strlen(lic) != 18) return 0;
if (strncmp(lic, "YRR-", 4) != 0) return 0;
if (lic[8] != '-' || lic[13] != '-') return 0;
hex4(lic+4,  &a); hex4(lic+9,  &b); hex4(lic+14, &c);
if (a < 0x1000 || a > 0x7FFF) return 0;
if ((a & 0x1000) == 0) return 0;
if (b != permutar(a)) return 0;
// armar buffer "YRR" + a + b en ASCII y comparar con c
```

## 3. La permutación

`permutar` carga cada bit `i` de `a` y lo escribe en la posición `T[i]`. La tabla `T` queda a la vista en el pseudocódigo como un arreglo de 16 bytes:

```
T = {7, 12, 3, 10, 0, 14, 5, 9, 15, 2, 11, 6, 1, 13, 4, 8}
```

## 4. El checksum

La función que compara con `c` consume 11 bytes y recorre un lazo con el polinomio `0x1021` e init `0xFFFF`. Firma inconfundible de **CRC-16/CCITT (XMODEM-16)**:

```c
crc = 0xFFFF;
for (byte in data) {
    crc ^= byte << 8;
    for (bit = 0; bit < 8; bit++)
        crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1);
}
```

## 5. Keygen

```python
A = randrange(0x1000, 0x8000) | 0x1000
B = permutar(A, T)
C = crc16_ccitt(f"YRR{A:04X}{B:04X}".encode())
lic = f"YRR-{A:04X}-{B:04X}-{C:04X}"
```

Ver [`muestras/keygen_yarara.py`](../../muestras/keygen_yarara.py). El test `test_keygen_yarara_valida_en_el_crackme` prueba varios valores de `A` en los bordes del rango.

## 6. Lecciones

- Las tablas chicas (16 bytes) suelen quedar inline en el pseudocódigo — identificarlas es cuestión de reconocer el patrón del lazo.
- Los polinomios de CRC son otra firma conocida: `0x1021` → CCITT, `0xEDB88320` → CRC-32 reflejado, `0x82F63B78` → CRC-32C.
- Las restricciones de rango (`bit 12 = 1`, `a <= 0x7FFF`) acortan el espacio de claves válidas y dan buenos tests de regresión para el keygen.
