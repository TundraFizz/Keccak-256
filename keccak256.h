#include "libkeccak/libkeccak.h"
#include <sys/stat.h>
#include <malloc.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum representation {
  // Message digest representation formats
  REPRESENTATION_BINARY,     // Print the checksum in binary
  REPRESENTATION_UPPER_CASE, // Print the checksum in upper case hexadecimal
  REPRESENTATION_LOWER_CASE  // Print the checksum in lower case hexadecimal
};

char* run(const char* publicKey);

static char *restrict hashsum = NULL; // Storage for binary hash
static char *restrict hexsum = NULL;  // Storage for hexadecimal hash
char *argv0;

static void user_error(const char *text);

static void * emalloc(size_t n);

static void * erealloc(
  void *ptr,
  size_t n);

static void eperror(void);

static int generalised_sum_fd_hex(
  const char* publicKey,
  libkeccak_state_t *restrict state,
  const libkeccak_spec_t *restrict spec,
  const char *restrict suffix,
  char *restrict hash);

static int hash(
  const char *publicKey,
  const libkeccak_spec_t *restrict spec,
  const char *restrict suffix);

static int check(
  const libkeccak_spec_t *restrict spec,
  long squeezes,
  const char *restrict suffix,
  int hex,
  const char *restrict filename,
  const char *restrict correct_hash);

static int check_checksums(
  const char *restrict filename,
  const libkeccak_spec_t *restrict spec,
  long squeezes,
  const char *restrict suffix,
  enum representation style,
  int hex);

static int print_checksum(
  const char* publicKey,
  const libkeccak_spec_t *spec,
  const char *restrict suffix,
  enum representation style);
