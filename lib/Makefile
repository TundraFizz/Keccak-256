FLAGS = -fPIC -c -std=c99 -O3 -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700

all:
	make clean
	make build
	make precompiled

build:
	make CreateObjectFiles
	make CreateArchive
	g++ -std=c++11 -O3 -s ../test.cpp -L . -l :keccak256.a -o ../test
	valgrind --leak-check=yes --quiet ../test 20000
	# 3bb89452fe5544e057767a22e7b8a14e8338963e64fb146cd22746b543d339e8
	../test 1000000
	# 3bb89452fe5544e057767a22e7b8a14e8338963e64fb146cd22746b543d339e8

precompiled:
	g++ -std=c++11 -O3 -s ../test-pre.cpp -L ../precompiled -l :keccak256.a -o ../test-pre
	valgrind --leak-check=yes --quiet ../test-pre 20000
	# 3bb89452fe5544e057767a22e7b8a14e8338963e64fb146cd22746b543d339e8
	../test-pre 1000000
	# 3bb89452fe5544e057767a22e7b8a14e8338963e64fb146cd22746b543d339e8

CreateObjectFiles:
	g++ -c -O3 -s keccak256.cpp     -o keccak256.o
	gcc $(FLAGS) generalised-spec.c -o generalised-spec.o
	gcc $(FLAGS) digest.c           -o digest.o

CreateArchive:
	ar rc keccak256.a keccak256.o digest.o generalised-spec.o

clean:
	rm -f *.a *.o ../test ../test-pre
	clear
