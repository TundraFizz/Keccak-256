# Keccak-256

To compile the library

```
sudo yum -y install git gcc gcc-c++
git clone https://github.com/TundraFizz/Keccak-256
cd Keccak-256
make -C libkeccak
gcc -c -std=c99 -O3 -s keccak256.c -o keccak256.o
```

To test the library

```
g++ -O3 -s main.cpp keccak256.o -L precompiled/libkeccak -l :libkeccak.a -o myapp
./myapp
```
