#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stdio.h>

#define SHA1_BLOCK_SIZE 64

typedef enum {
  SHA1_OK = 0,
  SHA1_NULL,
  SHA1_SIZE,
} sha1_err;

typedef struct {
  int block_idx;
  uint8_t block[SHA1_BLOCK_SIZE];
  uint32_t hash[5];
  uint64_t message_length;
} sha1_ctx_t;

sha1_err sha1_init(sha1_ctx_t *ctx);
sha1_err sha1_feed(sha1_ctx_t *ctx, const uint8_t *data, size_t len);
sha1_err sha1_digest(sha1_ctx_t *ctx, uint8_t digest[20]);
uint32_t _sha1_rotate(uint32_t x, int n);
sha1_err _sha1_pad_block(sha1_ctx_t *ctx);
sha1_err _sha1_compress_block(sha1_ctx_t *ctx);

#endif // SHA1_H
