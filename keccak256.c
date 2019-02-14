#include "keccak256.h"

static void user_error(const char *text) {
  fprintf(stderr, "%s: %s\n", argv0, text);
  exit(2);
}

static void * emalloc(size_t n) {
  void *r = malloc(n);
  if (!r) {
    perror(argv0);
    exit(2);
  }
  return r;
}

static void * erealloc(void *ptr, size_t n) {
  if (!(ptr = realloc(ptr, n))) {
    perror(argv0);
    exit(2);
  }
  return ptr;
}

static void eperror(void) {
  perror(argv0);
  exit(2);
}

static int generalised_sum_fd_hex(
  const char* publicKey,
  libkeccak_state_t *restrict state,
  const libkeccak_spec_t *restrict spec,
  const char *restrict suffix,
  char *restrict hash
){
  struct stat attr;
  size_t blksize = 4096, r, w;
  char *restrict chunk;
  char even = 1, buf = 0, c;

  if (libkeccak_state_initialise(state, spec) < 0)
    return -1;

  // Set the blocksize to 129 because 128 bytes + 1 null byte at the end
  blksize = 129;

  chunk = malloc(blksize);

  r = w = 0;

  for (int i = 0; i < strlen(publicKey); i++){
    // printf("CHAR: %c\n", testing[i]);

    c = publicKey[i];

    if (isxdigit(c)) {
      buf = (buf << 4) | ((c & 15) + (c > '9' ? 9 : 0));
      if ((even ^= 1))
        chunk[w++] = buf;
    }
  }

  // w should ALWAYS be 64
  w = 64;

  if (libkeccak_fast_update(state, chunk, w) < 0) {
    free(chunk);
    return -1;
  }

  free(chunk);

  if (!even)
    user_error("file is malformated");

  return libkeccak_fast_digest(state, NULL, 0, 0, suffix, hash);
}

static int hash(
  const char *publicKey,
  const libkeccak_spec_t *restrict spec,
  const char *restrict suffix
){
  static size_t length = 0;
  libkeccak_state_t state;

  if (!length) {
    length = (size_t)((spec->output + 7) / 8);
    hashsum = emalloc(length * sizeof(char));
    hexsum = emalloc((length * 2 + 1) * sizeof(char));
  }

  if (generalised_sum_fd_hex(publicKey, &state, spec, suffix, hashsum))
    eperror();

  libkeccak_state_fast_destroy(&state);

  return 0;
}

static int check(
  const libkeccak_spec_t *restrict spec,
  long squeezes,
  const char *restrict suffix,
  int hex,
  const char *restrict filename,
  const char *restrict correct_hash
){
  size_t length = (size_t)((spec->output + 7) / 8);

  // I DO NOT CARE ABOUT THIS!

  // if (access(filename, F_OK) || hash(filename, spec, squeezes, suffix, hex)) {
  //   printf("%s: Missing\n", filename);
  //   return 1;
  // }

  libkeccak_unhex(hexsum, correct_hash);
  if (memcmp(hexsum, hashsum, length)) {
    printf("%s: Fail\n", filename);
    return 1;
  } else {
    printf("%s: OK\n", filename);
    return 0;
  }
}

static int check_checksums(const char *restrict filename, const libkeccak_spec_t *restrict spec,
long squeezes, const char *restrict suffix, enum representation style, int hex) {
  printf("check_checksums\n");
  struct stat attr;
  size_t blksize = 4096;
  size_t size = 4096;
  size_t ptr = 0;
  ssize_t got;
  char *buf;
  int fd = -1;
  int ret = 0;
  int stage;
  size_t hash_start = 0, hash_end = 0;
  size_t file_start = 0, file_end = 0;
  char *hash;
  char *file;
  size_t hash_n;
  char c;

  fd = open(strcmp(filename, "-") ? filename : "/dev/stdin", O_RDONLY);
  if (fd < 0)
    eperror();

  if (!fstat(fd, &attr)) {
    if (attr.st_size > 0)
      blksize = (size_t)(attr.st_size);
    if (attr.st_size > 0)
      size = (size_t)(attr.st_size);
  }

  size = size > blksize ? size : blksize;
  buf = emalloc(size);

  for (;;) {
    if (ptr + blksize < size)
      buf = erealloc(buf, size <<= 1);

    got = read(fd, buf + ptr, blksize);
    if (got < 0)
      eperror();
    if (!got)
      break;
    ptr += (size_t)got;
  }
  if (ptr == size)
    buf = erealloc(buf, size + 1);
  size = ptr;
  close(fd), fd = -1;
  buf[size++] = '\n';

  for (ptr = 0, stage = 0; ptr < size; ptr++) {
    c = buf[ptr];
    if (stage == 0) {
      if (isxdigit(c))
        ;
      else if (c == ' ' || c == '\t')
        hash_end = ptr, stage++;
      else if (c == '\n' || c == '\f' || c == '\r')
        hash_end = ptr, stage = 3;
      else
        user_error("file is malformated");
    } else if (stage == 1) {
      if (c == '\n' || c == '\f' || c == '\r')
        stage = 3;
      else if (c != ' ' && c != '\t')
        file_start = ptr, stage++;
    } else if (stage == 2) {
      if (c == '\n' || c == '\f' || c == '\r')
        file_end = ptr, stage++;
    }

    if (stage == 3) {
      if ((hash_start == hash_end) != (file_start == file_end))
        user_error("file is malformated");
      if (hash_start != hash_end) {
        hash = buf + hash_start;
        file = buf + file_start;
        hash_n = hash_end - hash_start;
        buf[hash_end] = '\0';
        buf[file_end] = '\0';
        if (hash_n % 2)
          user_error("file is malformated");
        if (hash_n / 2 != (size_t)((spec->output + 7) / 8))
          user_error("algorithm parameter mismatch");

        // I DO NOT CARE ABOUT THIS!
        // ret |= check(spec, squeezes, suffix, hex, file, hash);

      }
      stage = 0;
      hash_start = hash_end = file_start = file_end = ptr + 1;
    }
  }

  if (stage)
    user_error("file is malformated");

  free(buf);
  close(fd);
  return ret;

  (void) style;
}

static int print_checksum(
  const char* publicKey,
  const libkeccak_spec_t *spec,
  const char *restrict suffix,
  enum representation style
){
  size_t p = 0, n = (size_t)((spec->output + 7) / 8);
  ssize_t w;

  if (hash(publicKey, spec, suffix)) {
    return 1;
  }

  if (style == REPRESENTATION_LOWER_CASE) {
    libkeccak_behex_lower(hexsum, hashsum, n);
  } else {
    fflush(stdout);
    for (; p < n; p += (size_t)w)
      if ((w = write(STDOUT_FILENO, &hashsum[p], n - p)) < 0)
        eperror();
  }

  return 0;
}

char* run(const char* publicKey){
  libkeccak_generalised_spec_t gspec;
  libkeccak_generalised_spec_initialise(&gspec);
  libkeccak_spec_sha3((libkeccak_spec_t *)&gspec, 256);
  const char *restrict suffix = "";

  enum representation style = REPRESENTATION_LOWER_CASE;
  libkeccak_spec_t spec;
  int r = 0;

  libkeccak_degeneralise_spec(&gspec, &spec);

  print_checksum(publicKey, &spec, suffix, style);

  free(hashsum);
  return hexsum;
}
