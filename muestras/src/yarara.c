/*
 * yarara.exe - segundo crackme para la demo de Tero.
 *
 * Más duro que carpincho: la clave de licencia pasa por una tabla de
 * permutación, un checksum CRC-16/CCITT y una restricción de rango por
 * grupo. El objetivo del writeup es recuperar la tabla y el polinomio
 * desde el binario sin símbolos. No hace nada fuera de leer stdin.
 *
 * Formato de la licencia: YRR-AAAA-BBBB-CCCC
 *   - AAAA, BBBB, CCCC: 4 dígitos hex (mayúsculas) cada uno.
 *   - AAAA en [0x1000, 0x7FFF] (bit 15 en 0, bit 12 en 1).
 *   - BBBB = permutar(AAAA) con la tabla T.
 *   - CCCC = CRC-16/CCITT (0x1021, init 0xFFFF) sobre "YRR" + AAAA + BBBB
 *            representados como ASCII.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Permutación de 16 bits. T[i] indica a qué posición va el bit i. */
static const uint8_t T[16] = {
     7, 12,  3, 10,  0, 14,  5,  9,
    15,  2, 11,  6,  1, 13,  4,  8
};

static uint16_t permutar(uint16_t x)
{
    uint16_t y = 0;
    for (int i = 0; i < 16; i++)
        if (x & (1u << i))
            y |= (uint16_t)(1u << T[i]);
    return y;
}

static uint16_t crc16_ccitt(const uint8_t *data, size_t n)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < n; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021)
                                 : (uint16_t)(crc << 1);
    }
    return crc;
}

static int hex4(const char *s, uint16_t *out)
{
    uint16_t v = 0;
    for (int i = 0; i < 4; i++) {
        char c = s[i];
        v <<= 4;
        if (c >= '0' && c <= '9')      v |= (uint16_t)(c - '0');
        else if (c >= 'A' && c <= 'F') v |= (uint16_t)(c - 'A' + 10);
        else                           return 0;
    }
    *out = v;
    return 1;
}

static int validar(const char *lic)
{
    uint16_t a, b, c;
    if (strlen(lic) != 18) return 0;
    if (strncmp(lic, "YRR-", 4) != 0) return 0;
    if (lic[8] != '-' || lic[13] != '-') return 0;
    if (!hex4(lic + 4,  &a)) return 0;
    if (!hex4(lic + 9,  &b)) return 0;
    if (!hex4(lic + 14, &c)) return 0;
    if (a < 0x1000 || a > 0x7FFF) return 0;
    if ((a & 0x1000) == 0)        return 0;
    if (b != permutar(a))         return 0;

    uint8_t buf[13];
    memcpy(buf, "YRR", 3);
    memcpy(buf + 3,  lic + 4,  4);
    memcpy(buf + 7,  lic + 9,  4);
    memcpy(buf + 11, "\0\0", 0);
    uint16_t crc = crc16_ccitt(buf, 11);
    return crc == c;
}

static void recortar(char *s) { s[strcspn(s, "\r\n")] = '\0'; }

int main(void)
{
    char lic[64];
    printf("== Yarara License v1.0 ==\n");
    printf("Licencia: ");
    if (!fgets(lic, sizeof lic, stdin)) return 2;
    recortar(lic);
    if (validar(lic)) {
        printf("OK\n");
        return 0;
    }
    printf("Licencia invalida.\n");
    return 1;
}
