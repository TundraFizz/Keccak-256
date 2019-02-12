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
cd Keccak-256/libkeccak
make
mv libkeccak.so libkeccak.so.1
cd ..
gcc -c -o kek.o kek.c -std=c99 -O3 -s
g++ -o myapp kek.o main-test.cpp -O3 -s -L libkeccak -l keccak -fpermissive
./myapp
```

```
cc -fPIC -c -o libkeccak/digest.o libkeccak/digest.c -std=c99 -O3 -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
cc -fPIC -c -o libkeccak/files.o libkeccak/files.c -std=c99 -O3 -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
cc -fPIC -c -o libkeccak/generalised-spec.o libkeccak/generalised-spec.c -std=c99 -O3 -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
cc -fPIC -c -o libkeccak/hex.o libkeccak/hex.c -std=c99 -O3 -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
cc -fPIC -c -o libkeccak/state.o libkeccak/state.c -std=c99 -O3 -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
cc -fPIC -c -o libkeccak/mac/hmac.o libkeccak/mac/hmac.c -std=c99 -O3 -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
ar rc libkeccak.a libkeccak/digest.o libkeccak/files.o libkeccak/generalised-spec.o libkeccak/hex.o libkeccak/state.o libkeccak/mac/hmac.o
ar -s libkeccak.a
cc -shared -Wl,-soname,libkeccak.so.1 -o libkeccak.so libkeccak/digest.o libkeccak/files.o libkeccak/generalised-spec.o libkeccak/hex.o libkeccak/state.o libkeccak/mac/hmac.o -s
cc  -O3 -c -o test.o test.c -std=c99 -O3 -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
cc  -o test test.o libkeccak.a -s
cc  -O3 -c -o benchmark.o benchmark.c -std=c99 -O3 -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
cc  -o benchmark benchmark.o libkeccak.a -s
```
