FLAGS = -fPIC -c -std=c99 -O3 -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700

all:
	clear
	make CreateObjectFiles
	make CreateArchive
	g++ -O3 -s main.cpp -L . -l :my-library.a -o myapp
	./myapp

CreateObjectFiles:
	g++ -c -O3 -s keccak256.cpp               -o keccak256.o
	gcc $(FLAGS) libkeccak/digest.c           -o digest.o
	gcc $(FLAGS) libkeccak/files.c            -o files.o
	gcc $(FLAGS) libkeccak/generalised-spec.c -o generalised-spec.o
	gcc $(FLAGS) libkeccak/hex.c              -o hex.o
	gcc $(FLAGS) libkeccak/state.c            -o state.o
	gcc $(FLAGS) libkeccak/hmac.c             -o hmac.o

CreateArchive:
	ar rc my-library.a keccak256.o digest.o files.o generalised-spec.o hex.o state.o hmac.o

clean:
	clear
	rm -f *.a *.o
