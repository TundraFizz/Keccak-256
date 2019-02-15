#include "libkeccak/keccak256.h"
#include <iostream>

int main(void){
  // Private Key
  // abcdef1203405600789001112233aabbcc24680abcdef00001234567890abcde

  const char* publicKey = "64c9992d70d56cf60383b86dcba395ee0ccdb780b13d1b52803b010ae62574b68ebc46f0b25acf3721da182a180b985500669ec8541244752ec1331ea61aacee";
  char* address = PublicKeyToAddress(publicKey);
  std::cout << address << "\n";

  // 3bb89452fe5544e057767a22e7b8a14e8338963e64fb146cd22746b543d339e8
  //                       0xe7B8a14E8338963E64fB146cd22746B543D339e8

  return 0;
}
