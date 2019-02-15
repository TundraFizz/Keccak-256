#include "wrapper.h"
#include <iostream>

int main(void){
  const char* publicKey = "836b35a026743e823a90a0ee3b91bf615c6a757e2b60b9e1dc1826fd0dd16106f7bc1e8179f665015f43c6c81f39062fc2086ed849625c06e04697698b21855e";
  const char* address   = PublicKeyToAddress(publicKey);
  // char* address = run(publicKey);
  std::cout << address << "\n";
  return 0;
}
