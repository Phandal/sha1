#include "sha256.h"

sha256_err sha256_init(sha256_ctx_t *ctx) {
  if (!ctx) {
    return SHA256_NULL;
  }

  ctx->block_idx = 0;
  ctx->message_length = 0;
  ctx->digested = 0;

  for (int x = 0; x < SHA256_BLOCK_SIZE; ++x) {
    ctx->block[x] = 0;
  }

  ctx->hash[0] = 0X6A09E667;
  ctx->hash[1] = 0XBB67AE85;
  ctx->hash[2] = 0X3C6EF372;
  ctx->hash[3] = 0XA54FF53A;
  ctx->hash[4] = 0X510E527F;
  ctx->hash[5] = 0X9B05688C;
  ctx->hash[6] = 0X1F83D9AB;
  ctx->hash[7] = 0X5BE0CD19;

  return SHA256_OK;
}
