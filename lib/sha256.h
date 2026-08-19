#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stdlib.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_HASH_SIZE 32

typedef enum {
  SHA256_OK = 0,
  SHA256_NULL,
  SHA256_SIZE,
  SHA256_CORRUPT,
} sha256_err;

typedef struct {
  int block_idx;
  uint8_t block[SHA256_BLOCK_SIZE];
  uint32_t hash[SHA256_HASH_SIZE / 4];
  uint64_t message_length;
  unsigned int digested;
} sha256_ctx_t;

sha256_err sha256_init(sha256_ctx_t *ctx);
sha256_err sha256_feed(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
sha256_err sha256_digest(sha256_ctx_t *ctx, uint8_t digest[SHA256_HASH_SIZE]);

#endif // SHA256_H
