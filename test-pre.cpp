#include "precompiled/keccak256.h"
#include <iostream>

// Only for debugging; testing code execution time
#include <chrono>
#define TIME_POINT       std::chrono::high_resolution_clock::time_point
#define NOW              std::chrono::high_resolution_clock::now()
#define DIFFERENCE(a, b) std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count()
#define SHORTEN(a)       (float)a/(float)1000

const char alphanum[] = "0123456789abcdef";

char* RandomString(){
  char* temp = new char[129];

  for(int i = 0; i < 128; ++i) {
    temp[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
  }

  temp[128] = 0;
  return temp;
}

int main(int argc, char *argv[]){
  std::cout << "==================== BEGIN TESTS ====================\n";

  int keysToGenerate = atoi(argv[1]);
  std::cout << "Testing with " << keysToGenerate << " keys\n";

  char **keyring = new char *[keysToGenerate];

  for(int i = 0; i < keysToGenerate; ++i){
    keyring[i] = RandomString();
  }

  TIME_POINT t1 = NOW;

  for(int i = 0; i < keysToGenerate; ++i){
    char* address = PublicKeyToAddress(keyring[i]);

    // free(address);
    delete[] keyring[i];

    keyring[i] = address;
    // std::cout << keyring[i] << "\n";
  }

  TIME_POINT t2 = NOW;
  std::cout << "DURATION IN SECONDS: " << SHORTEN(DIFFERENCE(t1, t2)) << "\n";

  for(int i = 0; i < keysToGenerate; ++i){
    // delete[] keyring[i];
    free(keyring[i]);
  }

  delete[] keyring;

  // Private Key
  // abcdef1203405600789001112233aabbcc24680abcdef00001234567890abcde
  const char* publicKeySingle = "64c9992d70d56cf60383b86dcba395ee0ccdb780b13d1b52803b010ae62574b68ebc46f0b25acf3721da182a180b985500669ec8541244752ec1331ea61aacee";
  char* address = PublicKeyToAddress(publicKeySingle);
  std::cout << "# " << address << "\n";
  // 3bb89452fe5544e057767a22e7b8a14e8338963e64fb146cd22746b543d339e8
  //                       0xe7B8a14E8338963E64fB146cd22746B543D339e8

  // std::cout << "===================== END TESTS =====================\n";
  return 0;
}
