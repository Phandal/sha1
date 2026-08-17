#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHA1_BLOCK_SIZE 64

typedef enum {
  SHA1_OK = 0,
  SHA1_NULL,
} sha1_err;

typedef struct {
  int block_idx;
  uint8_t block[SHA1_BLOCK_SIZE];
} sha1_ctx_t;

sha1_ctx_t *sha1_init();
sha1_err sha1_feed(sha1_ctx_t *ctx, const uint8_t *data, size_t len);
sha1_err sha1_digest(sha1_ctx_t *ctx, uint8_t digest[20]);
void sha1_destroy(sha1_ctx_t *ctx);
sha1_err _sha1_compress_block(sha1_ctx_t *ctx);

sha1_ctx_t *sha1_init() {
  sha1_ctx_t *ctx = calloc(1, sizeof(sha1_ctx_t));
  if (!ctx) {
    return NULL;
  }

  ctx->block_idx = 0;
  return ctx;
}

sha1_err sha1_feed(sha1_ctx_t *ctx, const uint8_t *data, size_t len) {
  sha1_err err;

  if (!ctx || !data) {
    return SHA1_NULL;
  }

  for (size_t x = 0; x < len; ++x) {
    if (ctx->block_idx == SHA1_BLOCK_SIZE) {
      err = _sha1_compress_block(ctx);
      if (err != SHA1_OK) {
        return err;
      }
    }

    ctx->block[ctx->block_idx++] = data[x];
  }

  return SHA1_OK;
}

sha1_err sha1_digest(sha1_ctx_t *ctx, uint8_t digest[20]) {
  if (!ctx) {
    return SHA1_NULL;
  }

  memmove(digest, "Digest Here", 12);
  return SHA1_OK;
}

void sha1_destory(sha1_ctx_t *ctx) {
  if (!ctx) {
    return;
  }

  free(ctx);
  ctx = NULL;
}

sha1_err _sha1_compress_block(sha1_ctx_t *ctx) {
  // TODO: actually do the sha1 hash on the block here
  printf("Compressing Block:\n");
  for (int i = 0; i < SHA1_BLOCK_SIZE; ++i) {
    printf("%02X", ctx->block[i]);
    ctx->block[i] = '\0';
  }
  printf("\n");

  ctx->block_idx = 0;
  return SHA1_OK;
}

int main(void) {
  sha1_err err;
  uint8_t digest[20];
  size_t len;
  uint8_t data[512];
  // uint8_t data[3] = {'a', 'b', 'c'};

  sha1_ctx_t *ctx = sha1_init();
  if (!ctx) {
    fprintf(stderr, "Could not initialize sha1 context\n");
    return 1;
  }

  while ((len = fread(data, 1, 512, stdin)) > 0) {
    err = sha1_feed(ctx, data, len);
    if (err != SHA1_OK) {
      fprintf(stderr, "sha1 feed error\n");
      return 1;
    }
  }

  err = sha1_digest(ctx, digest);
  if (err != SHA1_OK) {
    fprintf(stderr, "sha1 digest error\n");
    return 1;
  }

  printf("Digest:\n");
  for (int i = 0; i < 20; ++i) {
    printf("%0X", digest[i]);
  }
  printf("\n");

  sha1_destory(ctx);
  return 0;
}

/*
1. Pad messge (append byte 0x80, fill with zeros, last 8 bytes are for the
original message length)
2. Split into 512 bit (64 byte) blocks, then do 3-5 for each block
3. Initialize the 5 hash state variables to their initialization vector
4. Split block into 16 'Words' (2 Bytes or 16 bits), then complete 80 round of
compression with chaing F and K every 20 rounds 4a. Expand the 'Word' into 180
bits with the fomula W[i] = ROTL(W[i-3] XOR W[i-8] XOR W[i-14] XOR W[i-16], 1)


| Rounds | Logical Function f(b, c, d)         | Constant K | Function Name |
|——–-----|——————————---------------------------|——————------|—————----------|
| 0–19   | (b AND c) OR ((NOT b) AND d)        | 0x5A827999 | Choice (Ch)   |
| 20–39  | b XOR c XOR d                       | 0x6ED9EBA1 | Parity        |
| 40–59  | (b AND c) OR (b AND d) OR (c AND d) | 0x8F1BBCDC | Majority (Maj)|
| 60–79  | b XOR c XOR d                       | 0xCA62C1D6 | Parity        |
*/
