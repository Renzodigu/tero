# Compila las muestras para analizar con Tero.
# Requiere MinGW-w64 (gcc en PATH) o el toolchain de Windows SDK (cl.exe).
#
#   mingw32-make        -> compila carpincho.exe y yarara.exe en bin/
#   mingw32-make clean  -> borra bin/
#
# Se compila con -O2 y símbolos despojados para que el analisis sea
# más representativo de un binario sin DWARF ni PDB.

CC      ?= gcc
CFLAGS  ?= -O2 -s -static -Wall -Wextra
BIN_DIR := bin
TARGETS := $(BIN_DIR)/carpincho.exe $(BIN_DIR)/yarara.exe

.PHONY: all clean
all: $(TARGETS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/carpincho.exe: src/carpincho.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(BIN_DIR)/yarara.exe: src/yarara.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BIN_DIR)
