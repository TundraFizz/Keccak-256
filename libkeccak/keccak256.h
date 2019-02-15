extern "C" {
  #include "libkeccak.h"
}
#include <sys/stat.h>
#include <ctype.h>

static char* hashsum = NULL;
static char* hexsum  = NULL;
static void* emalloc(size_t n);
int generalised_sum_fd_hex(const char* publicKey, libkeccak_state_t* state, const libkeccak_spec_t* spec, char* hash);
int hash(const char* publicKey, const libkeccak_spec_t* spec);
int print_checksum(const char* publicKey, const libkeccak_spec_t* spec);
char* run(const char* publicKey);
