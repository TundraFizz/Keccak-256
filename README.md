# Keccak-256

The below is for building on a CentOS system

Install Git, GCC, and G++
```
sudo yum -y install git gcc gcc-c++
```

Make libkeccak, install it, and then set the path - rebooting afterwards
```
git clone https://github.com/TundraFizz/Keccak-256
cd Keccak-256/libkeccak
make
sudo make install PREFIX=/usr
echo "export LD_LIBRARY_PATH=/usr/lib" >> ~/.bashrc
sudo reboot
```

```
cd Keccak-256
gcc -c kek.c -std=c99 -O3 -s -l keccak
g++ -o myapp kek.o main-test.cpp -O3 -s -l keccak -fpermissive
./myapp
```
