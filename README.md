# Keccak-256

The below is for building on a CentOS system

Install Git, GCC, and G++

```
sudo yum -y install git gcc gcc-c++
```

Get the repository and make libkeccak, changing `libkeccak.so` to `libkeccak.so.1`
Then compile `myapp` and test it

```
git clone https://github.com/TundraFizz/Keccak-256
cd Keccak-256
make -C libkeccak
gcc -c -o kek.o kek.c -std=c99 -O3 -s
g++ -o myapp kek.o main.cpp -O3 -s -L libkeccak -l :libkeccak.a
./myapp
```
