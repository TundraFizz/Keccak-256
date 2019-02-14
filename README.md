# Keccak-256

```
sudo yum -y install git gcc gcc-c++
git clone https://github.com/TundraFizz/Keccak-256
cd Keccak-256
make -C libkeccak
gcc -c -o kek.o kek.c -std=c99 -O3 -s
g++ -o myapp kek.o main.cpp -O3 -s -L libkeccak -l :libkeccak.a
./myapp
```
