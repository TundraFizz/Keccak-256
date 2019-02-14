#include <iostream>

#ifdef __cplusplus
#   ifdef __GNUC__
#       define restrict __restrict__ // G++ has restrict
#   else
#       define restrict // C++ in general doesn't
#   endif
#endif

extern "C" {
  #include "keccak256.h"
}

int main(){
  run("public.key");
  return 0;
}
