BOFNAME := ghostkatz
BIN_DIR := bin

CC_x64  := x86_64-w64-mingw32-gcc
CC_x86  := i686-w64-mingw32-gcc

.PHONY: all clean x86 x64

all: clean $(BIN_DIR) x86 x64

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

x86:
	$(CC_x86) -o $(BIN_DIR)/$(BOFNAME).x86.o -Os -c src/main.c

x64:
	$(CC_x64) -o $(BIN_DIR)/$(BOFNAME).x64.o -Os -c src/main.c

clean:
	rm -f $(BIN_DIR)/$(BOFNAME).*.o
