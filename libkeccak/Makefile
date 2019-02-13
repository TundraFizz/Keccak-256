CFLAGS   = -std=c99 -O3
CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
LDFLAGS  = -s

OBJ =\
	libkeccak/digest.o\
	libkeccak/files.o\
	libkeccak/generalised-spec.o\
	libkeccak/hex.o\
	libkeccak/state.o\
	libkeccak/mac/hmac.o

all:
	clear
	make libkeccak.a

libkeccak.a: $(OBJ)
	$(AR) rc $@ $?
	$(AR) -s $@

.c.o:
	gcc -fPIC -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

test:
	clear
	make clean
	make all
	gcc -c -o ../kek.o ../kek.c -std=c99 -O3 -s
	g++ -O3 -s -fpermissive  ../kek.o ../main.cpp -L . -l keccak  -o ../myapp
	../myapp

install:
	ln -s libkeccak.so libkeccak.so.1

clean:
	clear
	-rm -f -- libkeccak.a libkeccak.so* *.o libkeccak/*.o libkeccak/mac/*.o
