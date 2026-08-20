#include <stdio.h>
#include <string.h>

#include "sha1.h"
#include "sha256.h"

int sha1_main(void);
int sha256_main(void);

int sha1_main(void) {
  sha1_ctx_t ctx;
  sha1_err err;
  uint8_t digest[SHA1_HASH_SIZE];
  size_t len;
  uint8_t data[512];

  err = sha1_init(&ctx);
  if (err != SHA1_OK) {
    fprintf(stderr, "could not initialize sha1 context\n");
    return err;
  }

  while ((len = fread(data, 1, 512, stdin)) > 0) {
    err = sha1_feed(&ctx, data, len);
    if (err != SHA1_OK) {
      fprintf(stderr, "sha1 feed error\n");
      return err;
    }
  }

  err = sha1_digest(&ctx, digest);
  if (err != SHA1_OK) {
    fprintf(stderr, "sha1 digest error\n");
    return err;
  }

  for (int i = 0; i < SHA1_HASH_SIZE; ++i) {
    printf("%02x", digest[i]);
  }
  printf("\n");

  return 0;
}

int sha256_main(void) {
  sha256_ctx_t ctx;
  sha256_err err;
  uint8_t digest[SHA256_HASH_SIZE];
  size_t len;
  uint8_t data[512];

  err = sha256_init(&ctx);
  if (err != SHA256_OK) {
    return fprintf(stderr, "could not initialize sha256 context\n");
    return err;
  }

  while ((len = fread(data, 1, 512, stdin)) > 0) {
    err = sha256_feed(&ctx, data, len);
    if (err != SHA256_OK) {
      fprintf(stderr, "sha256 feed error: %d\n", err);
      return err;
    }
  }

  err = sha256_digest(&ctx, digest);
  if (err != SHA256_OK) {
    fprintf(stderr, "sha256 digest error\n");
    return err;
  }

  for (int i = 0; i < SHA256_HASH_SIZE; ++i) {
    printf("%02x", digest[i]);
  }
  printf("\n");

  return 0;
}

void usage() { fprintf(stderr, "usage: hash {sha1|sha256}\n"); }

int main(int argc, char **argv) {

  if (argc != 2) {
    usage();
    return 1;
  }

  if (strcmp(argv[1], "sha1") == 0) {
    return sha1_main();
  } else if (strcmp(argv[1], "sha256") == 0) {
    return sha256_main();
  } else {
    usage();
    return 1;
  }
}
