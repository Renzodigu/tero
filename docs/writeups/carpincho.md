# Writeup: `carpincho.exe`

Objetivo: recuperar el algoritmo de validación de serial sin ver el código fuente, y escribir un keygen.

El binario está compilado con MinGW-w64, `-O2 -s -static`: sin símbolos y optimizado. Los fragmentos de pseudocódigo de este writeup son la salida real de Ghidra 12.1.4 a través de Tero, recortada pero sin renombrar; los nombres legibles aparecen recién en la sección 3.

## 1. Reconocimiento con Tero

```bash
tero analyze muestras/bin/carpincho.exe --out reportes/carpincho/
```

Tarda unos 30 segundos. Ghidra encuentra 54 funciones propias y el informe (`reportes/carpincho/carpincho.md`) marca dos cosas:

- **TERO-IMP-DYN-001**: el binario resuelve APIs con `LoadLibraryA`/`GetProcAddress`. Es código de arranque de MinGW, no del crackme: ruido esperable.
- **TERO-FUN-LICENCIA-001**: dos funciones llaman a `strncmp`, `FUN_140002ce5` y `FUN_140003460`.

Las dos candidatas no valen lo mismo, y descartar la equivocada es parte del trabajo:

- `FUN_140002ce5` recorre las cabeceras de sección del PE (`IMAGE_SECTION_HEADER`) y compara sus nombres con `strncmp(..., 8)`. Antes llama a `FUN_140002bd0`, que chequea las firmas `MZ`, `PE` y el *magic* `0x20b` de PE32+. Es `_FindPESectionByName` de la CRT de MinGW (con `_ValidateImageBase`): un **falso positivo** de la regla.
- `FUN_140003460` imprime `"== Carpincho Soft v1.0 =="`, lee dos líneas con `fgets` e imprime `"Licencia valida. Gracias por su compra."` o `"Licencia invalida."`. Es `main`, y ahí está la validación.

## 2. `main` tal como lo muestra Ghidra

Con `-O2`, el compilador metió la validación, el hash y el bloque de control dentro de `main`: no hay funciones separadas que buscar. Lo relevante del pseudocódigo:

```c
sVar5 = strlen((char *)local_88);
if (((((2 < sVar5) && (sVar5 = strlen(local_48), sVar5 == 0xd)) &&
     (iVar2 = strncmp(local_48,"CRP-",4), iVar2 == 0)) &&
    ((local_40 == '-' && (uVar8 = FUN_140001760(local_44,&local_8c), (int)uVar8 != 0)))) &&
   (uVar8 = FUN_140001760(local_3f,&local_8a), (int)uVar8 != 0)) {
  uVar7 = 0x811c9dc5;
  for (pbVar6 = local_88; *pbVar6 != 0; pbVar6 = pbVar6 + 1) {
    uVar7 = (uVar7 ^ *pbVar6) * 0x1000193;
  }
  uVar1 = (ushort)(uVar7 >> 0x10) ^ (ushort)uVar7;
  if ((uVar1 == local_8c) && ((ushort)((uVar1 << 5 | uVar1 >> 0xb) ^ 0xcafe) == local_8a)) {
    puts("Licencia valida. Gracias por su compra.");
    return 0;
  }
}
```

Para leerlo:

- `local_88` es el usuario y `local_48` el serial: son los buffers que llenan los dos `fgets`.
- `local_44`, `local_40` y `local_3f` no son variables distintas: son posiciones dentro del serial (`local_48 + 4`, `+ 8` y `+ 9`). Ghidra parte el buffer en pedazos porque el código accede a esos offsets directamente.
- `FUN_140001760` convierte 4 caracteres hexadecimales en mayúsculas a un número de 16 bits y devuelve 0 si alguno no es válido (resta `0x30` a los dígitos y `0x37` a las letras).

## 3. Renombrado

```c
if (strlen(usuario) < 3 || strlen(serial) != 13) invalida();
if (strncmp(serial, "CRP-", 4) != 0 || serial[8] != '-') invalida();
if (!hex4(serial + 4, &a) || !hex4(serial + 9, &b)) invalida();

h = 0x811C9DC5;
for (p = usuario; *p; p++)
    h = (h ^ *p) * 0x01000193;
hash = (h >> 16) ^ (h & 0xFFFF);

valida = a == hash && b == (rotl16(hash, 5) ^ 0xCAFE);
```

Los dos números mágicos (`0x811C9DC5`, el *offset basis*, y `0x01000193`, el primo) son la firma de **FNV-1a de 32 bits**, plegado a 16 bits con un XOR de las dos mitades. `(x << 5 | x >> 11)` sobre 16 bits es una rotación a la izquierda de 5.

## 4. Keygen

```python
A = fnv1a_16(nombre)
B = rol16(A, 5) ^ 0xCAFE
serial = f"CRP-{A:04X}-{B:04X}"
```

Ver [`muestras/keygen_carpincho.py`](../../muestras/keygen_carpincho.py). El test `test_keygen_carpincho_valida_en_el_crackme` genera seriales para varios usuarios y los pasa por el binario; todos vuelven con `Licencia valida`.

## 5. Lecciones

- Las constantes son el camino más corto para identificar algoritmos conocidos. FNV, CRC, MD5 y AES tienen firmas numéricas inconfundibles.
- Con optimización, las funciones chicas desaparecen dentro de quien las llama. Buscar `hash_nombre` como función aparte no lleva a nada; hay que buscar el patrón dentro de `main`.
- Las reglas de Tero no resuelven el crackme: señalan dónde mirar, y también señalan código de la CRT. Distinguir el código del programa del de la biblioteca (por las strings, por las cabeceras PE que recorre) es trabajo del analista.
