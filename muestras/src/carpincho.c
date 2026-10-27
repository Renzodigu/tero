/*
 * carpincho.exe - crackme de juguete para la demo de Tero.
 *
 * Pide un nombre de usuario y un número de serie con formato CRP-XXXX-XXXX
 * (hexadecimal en mayúsculas). El serial depende del nombre:
 *   - el primer bloque es un hash FNV-1a de 16 bits del nombre;
 *   - el segundo bloque es el primero rotado y mezclado con una constante.
 * El objetivo del writeup es recuperar este algoritmo desde el binario sin
 * símbolos y escribir un keygen. No hace nada fuera de leer stdin.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static uint16_t hash_nombre(const char *nombre)
{
    uint32_t h = 0x811C9DC5u;
    for (const unsigned char *p = (const unsigned char *)nombre; *p; p++) {
        h ^= *p;
        h *= 0x01000193u;
    }
    return (uint16_t)(h ^ (h >> 16));
}

static uint16_t bloque_control(uint16_t a)
{
    uint16_t r = (uint16_t)((a << 5) | (a >> 11));
    return (uint16_t)(r ^ 0xCAFE);
}

static int hex4(const char *s, uint16_t *out)
{
    uint16_t v = 0;
    for (int i = 0; i < 4; i++) {
        char c = s[i];
        v <<= 4;
        if (c >= '0' && c <= '9')
            v |= (uint16_t)(c - '0');
        else if (c >= 'A' && c <= 'F')
            v |= (uint16_t)(c - 'A' + 10);
        else
            return 0;
    }
    *out = v;
    return 1;
}

static int validar_serial(const char *nombre, const char *serial)
{
    uint16_t a, b;
    if (strlen(nombre) < 3 || strlen(serial) != 13)
        return 0;
    if (strncmp(serial, "CRP-", 4) != 0 || serial[8] != '-')
        return 0;
    if (!hex4(serial + 4, &a) || !hex4(serial + 9, &b))
        return 0;
    return a == hash_nombre(nombre) && b == bloque_control(a);
}

static void recortar(char *s)
{
    s[strcspn(s, "\r\n")] = '\0';
}

int main(void)
{
    char nombre[64], serial[64];

    printf("== Carpincho Soft v1.0 ==\n");
    printf("Usuario: ");
    if (!fgets(nombre, sizeof nombre, stdin))
        return 2;
    printf("Serial: ");
    if (!fgets(serial, sizeof serial, stdin))
        return 2;
    recortar(nombre);
    recortar(serial);

    if (validar_serial(nombre, serial)) {
        printf("Licencia valida. Gracias por su compra.\n");
        return 0;
    }
    printf("Licencia invalida.\n");
    return 1;
}
