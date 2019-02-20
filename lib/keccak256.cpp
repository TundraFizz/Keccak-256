#include "keccak256.h"

static void* emalloc(size_t n){
  void* r = malloc(n);

  if(!r)
    return (void*)-1;

  return r;
}

int generalised_sum_fd_hex(const char* publicKey, libkeccak_state_t* state, const libkeccak_spec_t* spec, char* hash){
  struct stat attr;
  size_t blksize = 129; // Set the blocksize to 129 because 128 bytes + 1 null byte at the end
  size_t r = 0;
  size_t w = 0;
  char* chunk;
  char even = 1;
  char buf = 0;
  char c;

  if(libkeccak_state_initialise(state, spec) < 0)
    return -1;

  chunk = (char*)malloc(blksize);

  for(int i = 0; i < strlen(publicKey); i++){
    c = publicKey[i];

    if(isxdigit(c)){
      buf = (buf << 4) | ((c & 15) + (c > '9' ? 9 : 0));
      if((even ^= 1))
        chunk[w++] = buf;
    }
  }

  w = 64; // w should ALWAYS be 64

  if(libkeccak_fast_update(state, chunk, w) < 0){
    free(chunk);
    return -1;
  }

  free(chunk);

  if(!even)
    return -1;

  libkeccak_fast_digest(state, NULL, 0, 0, "", hash);
  return 0;
}

int hash(const char* publicKey, const libkeccak_spec_t* spec){
  libkeccak_state_t state;
  static size_t length = 0;
  length  = (size_t)((spec->output + 7) / 8);
  hashsum = (char*)emalloc(length * sizeof(char));
  hexsum  = (char*)emalloc((length * 2 + 1) * sizeof(char));

  if(generalised_sum_fd_hex(publicKey, &state, spec, hashsum) == -1)
    return -1;

  libkeccak_state_fast_destroy(&state);
  return 0;
}

void libkeccak_behex_lower(char* output, const char* hashsum, size_t n){
  output[2 * n] = '\0';
  while (n--) {
    output[2 * n + 0] = "0123456789abcdef"[(hashsum[n] >> 4) & 15];
    output[2 * n + 1] = "0123456789abcdef"[(hashsum[n] >> 0) & 15];
  }
}

int print_checksum(const char* publicKey, const libkeccak_spec_t* spec){
  size_t n = (size_t)((spec->output + 7) / 8);

  if(hash(publicKey, spec) == -1)
    return -1;

  libkeccak_behex_lower(hexsum, hashsum, n);
  return 0;
}

char* PublicKeyToAddress(const char* publicKey){
  libkeccak_generalised_spec_t gspec;
  libkeccak_spec_t              spec;

  libkeccak_generalised_spec_initialise(&gspec);
  libkeccak_spec_sha3((libkeccak_spec_t *)&gspec, 256);

  libkeccak_degeneralise_spec(&gspec, &spec);

  if(print_checksum(publicKey, &spec) == -1)
    return (char*)-1;

  //                      24 | 40
  // 3bb89452fe5544e057767a22|e7b8a14e8338963e64fb146cd22746b543d339e8
  //                         |e7B8a14E8338963E64fB146cd22746B543D339e8
  char* address = new char[43];
  address[0] = '0';
  address[1] = 'x';
  memcpy(&address[2], &hexsum[24], 40);
  address[42] = '\0';

  free(hexsum);
  free(hashsum);

  return address;
}
