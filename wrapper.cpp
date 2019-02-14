#include "wrapper.h"
#define restrict // C++ doesn't have the restrict keyword

extern "C" {
  #include "keccak256.h"
}

const char* PublicKeyToAddress(const char* publicKey){
  const char* address = run(publicKey);
  return address;
}
