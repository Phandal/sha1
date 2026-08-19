#include <stdio.h>
#include <string.h>

#include "sha1.h"
#include "sha256.h"

int sha1(void);
int sha256(void);

int sha1(void) {
  sha1_ctx_t ctx;
  sha1_err err;
  uint8_t digest[SHA1_HASH_SIZE];
  size_t len;
  uint8_t data[512];

  err = sha1_init(&ctx);
  if (err != SHA1_OK) {
    fprintf(stderr, "could not initialize sha1 context\n");
    return 1;
  }

  while ((len = fread(data, 1, 512, stdin)) > 0) {
    err = sha1_feed(&ctx, data, len);
    if (err != SHA1_OK) {
      fprintf(stderr, "sha1 feed error\n");
      return 1;
    }
  }

  err = sha1_digest(&ctx, digest);
  if (err != SHA1_OK) {
    fprintf(stderr, "sha1 digest error\n");
    return 1;
  }

  for (int i = 0; i < SHA1_HASH_SIZE; ++i) {
    printf("%02x", digest[i]);
  }
  printf("\n");

  return 0;
}

int sha256(void) {
  sha256_ctx_t ctx;
  sha256_err err;

  err = sha256_init(&ctx);
  if (err != SHA256_OK) {
    return fprintf(stderr, "could not initialize sha256 context\n");
    return 1;
  }

  return 0;
}

void usage() { fprintf(stderr, "usage: hash {sha1|sha256}\n"); }

int main(int argc, char **argv) {

  if (argc != 2) {
    usage();
    return 1;
  }

  if (strcmp(argv[1], "sha1") == 0) {
    return sha1();
  } else if (strcmp(argv[1], "sha256") == 0) {
    return sha256();
  } else {
    usage();
    return 1;
  }
}
