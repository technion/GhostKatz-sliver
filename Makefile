BOFNAME := ghostkatz


CC_x64  := x86_64-w64-mingw32-gcc


.PHONY: all clean x64

all: clean x64

x64:
	$(CC_x64) -o $(BOFNAME).x64.o -Os -c src/main.c -Wno-pointer-to-int-cast -Wno-int-conversion

clean:
	rm -f $(BOFNAME).*.o
