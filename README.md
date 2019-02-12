# CentOS on AWS

Install Git, GCC, and G++
```
sudo yum -y install git gcc gcc-c++
```

Make and install libkeccak
```
git clone https://github.com/maandree/libkeccak
cd libkeccak
make
sudo make install PREFIX=/usr
```

Make
```
git clone https://github.com/maandree/sha3sum
cd sha3sum
make
sudo make install
```

Set the path
```
echo "export LD_LIBRARY_PATH=/usr/lib" >> ~/.bashrc
sudo reboot
```

You can now use the "keccak-256sum" command
```
echo "836b35a026743e823a90a0ee3b91bf615c6a757e2b60b9e1dc1826fd0dd16106f7bc1e8179f665015f43c6c81f39062fc2086ed849625c06e04697698b21855e" > public.key
keccak-256sum -x -l public.key
```

```
gcc -c kek.c -std=c99 -O3 -s -l keccak
g++ -o myapp kek.o main-test.cpp -O3 -s -l keccak -fpermissive
./myapp
72f15d6555488541650ce62c0bed7abd61247635c1973eb38474a2516ed1d884
```
