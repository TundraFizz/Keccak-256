# Keccak-256

Getting started

```
sudo yum -y install git gcc gcc-c++
git clone https://github.com/TundraFizz/Keccak-256
cd Keccak-256
```

Build and/or compile and test by performing one of these commands

| Command                   | Description                                |
| ------------------------- | ------------------------------------------ |
| `make -C lib precompiled` | Build the library from scratch and test it |
| `make -C lib build`       | Test the precompiled library               |
| `make -C lib`             | Run both of the above tests                |

#### TODO

```
# 3.4 seconds
# keccak256.h
#   1. generalised-spec.h -> spec.h
#   2. digest.h           -> spec.h
#
# generalised-spec.h has 100 lines of code in its .c and .h (200 total)
# spec.h             doesn't have a .c file                 (100 total)
# digest.h           has 750 lines of code in its .c        (1,000 total)
```
