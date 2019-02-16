FLAGS = -fPIC -c -std=c99 -O3 -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700

all:
	clear
	make CreateObjectFiles
	make CreateArchive
	g++ -std=c++11 -O3 -s ../main.cpp -L . -l :reeeeee.a -o ../test
	valgrind --leak-check=yes --quiet ../test

fast:
	clear
	make CreateObjectFiles
	make CreateArchive
	g++ -std=c++11 -O3 -s ../main.cpp -L . -l :reeeeee.a -o ../test
	../test
	# 3bb89452fe5544e057767a22e7b8a14e8338963e64fb146cd22746b543d339e8

CreateObjectFiles:
	g++ -c -O3 -s keccak256.cpp     -o keccak256.o
	gcc $(FLAGS) generalised-spec.c -o generalised-spec.o
	gcc $(FLAGS) digest.c           -o digest.o

CreateArchive:
	ar rc reeeeee.a keccak256.o digest.o generalised-spec.o

clean:
	clear
	rm -f *.a *.o

# 3.4 seconds
# keccak256.h
#   1. generalised-spec.h -> spec.h
#   2. digest.h           -> spec.h
#
# generalised-spec.h has 100 lines of code in its .c and .h (200 total)
# spec.h             doesn't have a .c file                 (100 total)
# digest.h           has 750 lines of code in its .c        (1,000 total)
