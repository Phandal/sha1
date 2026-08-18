#include <stdio.h>

#include "sha1.h"

int main(void) {
  sha1_ctx_t ctx;
  sha1_err err;
  uint8_t digest[20];
  size_t len;
  uint8_t data[512];

  err = sha1_init(&ctx);
  if (err != SHA1_OK) {
    fprintf(stderr, "Could not initialize sha1 context\n");
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

  // printf("Digest:\n");
  for (int i = 0; i < 20; ++i) {
    printf("%02x", digest[i]);
  }
  printf("\n");

  return 0;
}
