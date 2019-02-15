# Keccak-256

Getting started

```
sudo yum -y install git gcc gcc-c++
git clone https://github.com/TundraFizz/Keccak-256
cd Keccak-256
```

Using the precompiled binary

```
# gcc -c -std=c99 -O3 -s keccak256.c -o keccak256.o
g++ -c -O3 -s keccak256.cpp -o keccak256.o

# g++ -c -O3 -s wrapper.cpp -o wrapper.o
# g++ -O3 -s main.cpp wrapper.o keccak256.o -L precompiled -l :libkeccak.a -o myapp

g++ -O3 -s main.cpp keccak256.o -L precompiled -l :libkeccak.a -o myapp
./myapp
```

Compiling Keccak-256 yourself

```
make -C libkeccak
gcc -c -std=c99 -O3 -s keccak256.c -o keccak256.o
g++ -O3 -s main.cpp keccak256.o -L libkeccak -l :libkeccak.a -o myapp
./myapp
```
