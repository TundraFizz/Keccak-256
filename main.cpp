#include <iostream>

#define restrict // C++ doesn't have the restrict keyword

extern "C" {
  #include "keccak256.h"
}

int main(){
  char* test = run("public.key");
  std::cout << test << "\n";

  return 0;
}
