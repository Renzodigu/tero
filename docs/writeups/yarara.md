# Writeup: `yarara.exe`

Más duro que `carpincho`: la licencia pasa por una tabla de permutación de bits y un checksum CRC-16, y hay una restricción de rango.

Igual que en `carpincho`, el binario está compilado con MinGW-w64, `-O2 -s -static`, y los fragmentos de pseudocódigo son la salida real de Ghidra 12.1.4 a través de Tero, recortada pero sin renombrar.

## 1. Reconocimiento con Tero

```bash
tero analyze muestras/bin/yarara.exe --out reportes/yarara/
```

Hallazgos:

- **TERO-IMP-DYN-001**: resolución dinámica de APIs, del código de arranque de MinGW (ruido).
- **TERO-FUN-LICENCIA-001**: dos funciones llaman a `strncmp`. Una es `FUN_140002ce5`, el mismo falso positivo de la CRT que en `carpincho` (`_FindPESectionByName`). La otra es `FUN_140003460`, que imprime `"== Yarara License v1.0 =="` y termina en `"OK"` o `"Licencia invalida."`: es `main`, y adentro está toda la validación.

El binario no usa `memcmp`: todas las comparaciones finales son entre enteros de 16 bits.

## 2. Formato y restricciones

```c
sVar5 = strlen(local_48);
if ((((((sVar5 == 0x12) && (iVar3 = strncmp(local_48,"YRR-",4), iVar3 == 0)) &&
      (local_40 == '-')) &&
     ((local_3b == '-' && (uVar6 = FUN_140001760(local_44,&local_5e), (int)uVar6 != 0)))) &&
    ((uVar6 = FUN_140001760(local_3f,&local_5c), (int)uVar6 != 0 &&
     ((uVar6 = FUN_140001760(local_3a,&local_5a), (int)uVar6 != 0 &&
      ((ushort)(local_5e - 0x1000) < 0x7000)))))) && ((local_5e & 0x1000) != 0)) {
```

`local_48` es la licencia y `local_44`, `local_40`, `local_3f`, `local_3b` y `local_3a` son posiciones dentro de ella (`+4`, `+8`, `+9`, `+13` y `+14`). `FUN_140001760` convierte 4 caracteres hexadecimales a 16 bits. Queda:

```c
if (strlen(lic) != 18) invalida();
if (strncmp(lic, "YRR-", 4) != 0 || lic[8] != '-' || lic[13] != '-') invalida();
a = hex4(lic + 4); b = hex4(lic + 9); c = hex4(lic + 14);
if (a < 0x1000 || a > 0x7FFF) invalida();
if ((a & 0x1000) == 0) invalida();
```

La restricción de rango aparece como `(ushort)(a - 0x1000) < 0x7000`: el compilador convierte las dos comparaciones `a >= 0x1000 && a <= 0x7FFF` en una sola resta sin signo. Si `a` es menor que `0x1000`, la resta da la vuelta y queda un número enorme.

## 3. La permutación

```c
lVar7 = 0;
uVar9 = 0;
do {
  if ((local_5e >> ((uint)lVar7 & 0x1f) & 1) != 0) {
    uVar9 = uVar9 | 1 << ((&DAT_1400050a0)[lVar7] & 0x1f);
  }
  lVar7 = lVar7 + 1;
} while (lVar7 != 0x10);
if (local_5c == (ushort)uVar9) {
```

Para cada bit `i` de `a` que vale 1, prende el bit `T[i]` del resultado, y compara el resultado con `b`. La tabla `T` no está en el pseudocódigo: es `DAT_1400050a0`, 16 bytes en `.rdata`. Leyéndolos en Ghidra (o del archivo, en la RVA `0x50a0`):

```
T = {7, 12, 3, 10, 0, 14, 5, 9, 15, 2, 11, 6, 1, 13, 4, 8}
```

## 4. El checksum

```c
local_58[2] = 0x52;
lVar7 = 0;
local_58[0] = 0x59;
local_58[1] = 0x52;
uVar2 = 0xffff;
do {
  uVar2 = uVar2 ^ (ushort)local_58[lVar7] << 8;
  iVar3 = 8;
  do {
    uVar1 = uVar2 * 2;
    bVar10 = (short)uVar2 < 0;
    uVar2 = uVar1;
    if (bVar10) {
      uVar2 = uVar1 ^ 0x1021;
    }
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  lVar7 = lVar7 + 1;
} while (lVar7 != 0xb);
if (local_5a == uVar2) {
  puts("OK");
```

Recorre 11 bytes (`0xb`) con el polinomio `0x1021` y valor inicial `0xFFFF`, y compara con `c`. `(short)uVar2 < 0` es la forma en que Ghidra escribe «el bit 15 está prendido». Es **CRC-16/CCITT-FALSE** (en el catálogo actual de CRC, CRC-16/IBM-3740). Ojo con confundirla con XMODEM: usa el mismo polinomio pero arranca en `0x0000`, y el valor inicial es lo que distingue las variantes.

**Lo que el pseudocódigo no muestra.** Los bytes 0 a 2 del buffer son `0x59 0x52 0x52`, o sea `"YRR"`, pero no hay ninguna línea que escriba los bytes 3 a 10. Están en el desensamblado:

```
movd       xmm0, DWORD PTR [rsp+0x54]    ; lic + 4: los 4 caracteres de a
movd       xmm1, DWORD PTR [rsp+0x59]    ; lic + 9: los 4 caracteres de b
mov        BYTE PTR [rsp+0x42], 0x52     ; 'R'
mov        WORD PTR [rsp+0x40], 0x5259   ; 'Y' 'R'
punpckldq  xmm0, xmm1                    ; junta los dos grupos en 8 bytes
movq       QWORD PTR [rsp+0x43], xmm0    ; buffer + 3
```

El compilador copia los dos grupos de 4 caracteres con una sola escritura SSE de 8 bytes, y el decompilador la pierde. El buffer es entonces `"YRR"` + los caracteres de `a` + los de `b`, en ASCII tal como se tipearon: 3 + 4 + 4 = 11 bytes.

## 5. Keygen

```python
A = randrange(0x1000, 0x8000) | 0x1000
B = permutar(A, T)
C = crc16_ccitt(f"YRR{A:04X}{B:04X}".encode())
lic = f"YRR-{A:04X}-{B:04X}-{C:04X}"
```

Ver [`muestras/keygen_yarara.py`](../../muestras/keygen_yarara.py). El test `test_keygen_yarara_valida_en_el_crackme` prueba varios valores de `A` en los bordes del rango.

## 6. Lecciones

- Las tablas chicas no siempre quedan en el pseudocódigo: muchas veces son un `DAT_…` que hay que ir a leer a `.rdata`.
- El decompilador no es la verdad. Cuando un dato aparece de la nada (acá, 8 bytes del buffer del CRC), hay que bajar al desensamblado.
- Los polinomios de CRC son otra firma conocida: `0x1021` es CCITT, `0xEDB88320` es CRC-32 reflejado y `0x82F63B78` es CRC-32C. Pero el valor inicial y la reflexión también cuentan.
- Los compiladores reescriben las comparaciones: un rango `[0x1000, 0x7FFF]` se convierte en `(ushort)(a - 0x1000) < 0x7000`.
- Las restricciones de rango (`bit 12 = 1`, `a <= 0x7FFF`) achican el espacio de claves válidas y dan buenos tests de regresión para el keygen.
