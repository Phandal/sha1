#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHA1_BLOCK_SIZE 64

#define SHA1_ROTATE(x, n) (x << n | x >> (n - 1))

typedef enum {
  SHA1_OK = 0,
  SHA1_NULL,
} sha1_err;

typedef struct {
  int block_idx;
  uint8_t block[SHA1_BLOCK_SIZE];
  uint32_t hash[5];
} sha1_ctx_t;

sha1_err sha1_init(sha1_ctx_t *ctx);
sha1_err sha1_feed(sha1_ctx_t *ctx, const uint8_t *data, size_t len);
sha1_err sha1_digest(sha1_ctx_t *ctx, uint8_t digest[20]);
sha1_err _sha1_compress_block(sha1_ctx_t *ctx);

sha1_err sha1_init(sha1_ctx_t *ctx) {
  if (!ctx) {
    return SHA1_NULL;
  }

  ctx->block_idx = 0;

  ctx->hash[0] = 0X67452301;
  ctx->hash[1] = 0XEFCDAB89;
  ctx->hash[2] = 0X98BADCFE;
  ctx->hash[3] = 0X10325476;
  ctx->hash[4] = 0XC3D2E1F0;

  return SHA1_OK;
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

  for (int i = 0; i < 5; ++i) {
    digest[i * 4] = ctx->hash[i] >> 24;
    digest[i * 4 + 1] = ctx->hash[i] >> 16;
    digest[i * 4 + 2] = ctx->hash[i] >> 8;
    digest[i * 4 + 3] = ctx->hash[i];
  }

  return SHA1_OK;
}

sha1_err _sha1_compress_block(sha1_ctx_t *ctx) {
  uint32_t K[4] = { 0X5A827999, 0X6ED9EBA1, 0X8F1BBCDC, 0XCA62C1D6 };
  uint32_t W[80];
  int i;
  uint32_t temp, a, b, c, d, e;

  // 1. expand the block into an array of 80 words
  // Load the first 1n words into the W array
  for (i = 0; i < 16; ++i) {
    W[i] = ctx->block[i * 4] << 24;
    W[i] |= ctx->block[i * 4 + 1] << 16;
    W[i] |= ctx->block[i * 4 + 2] << 8;
    W[i] |= ctx->block[i * 4 + 3];
  }

  // Load the rest of the words in the W array with a formula
  // W[i] = ROTL(W[i-3] XOR W[i-8] XOR W[i-14] XOR W[i-16], 1)
  for (i = 16; i < 80; ++i) {
      W[i] = SHA1_ROTATE(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
  }

  // 2. Setup the initial working vars
  a = ctx->hash[0];
  b = ctx->hash[1];
  c = ctx->hash[2];
  d = ctx->hash[3];
  e = ctx->hash[4];

  // 3. Run 80 rounds of compression on the word array
  for (i = 0; i < 20; ++i) {
    temp = SHA1_ROTATE(a, 5) + ((b & c) | ((~b) & d)) + e + W[i] + K[0];
    e = d;
    d = c;
    c = SHA1_ROTATE(b, 30);
    b = a;
    a = temp;
  }

  for (i = 20; i < 40; ++i) {
    temp = SHA1_ROTATE(a, 5) + (b ^ c ^ d) + e + W[i] + K[1];
    e = d;
    d = c;
    c = SHA1_ROTATE(b, 30);
    b = a;
    a = temp;
  }

  for (i = 40; i < 60; ++i) {
    temp = SHA1_ROTATE(a, 5) + ((b & c) | (b & d) | (c & d)) + e + W[i] + K[2];
    e = d;
    d = c;
    c = SHA1_ROTATE(b, 30);
    b = a;
    a = temp;
  }

  for (i = 60; i < 80; ++i) {
    temp = SHA1_ROTATE(a, 5) + (b ^ c ^ d) + e + W[i] + K[3];
    e = d;
    d = c;
    c = SHA1_ROTATE(b, 30);
    b = a;
    a = temp;
  }

  ctx->hash[0] += a;
  ctx->hash[1] += b;
  ctx->hash[2] += c;
  ctx->hash[3] += d;
  ctx->hash[4] += e;
  
  ctx->block_idx = 0;
  return SHA1_OK;
}

int main(void) {
  sha1_ctx_t ctx;
  sha1_err err;
  uint8_t digest[20];
  size_t len;
  uint8_t data[512];
  // uint8_t data[3] = {'a', 'b', 'c'};

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

  printf("Digest:\n");
  for (int i = 0; i < 20; ++i) {
    printf("%0X", digest[i]);
  }
  printf("\n");

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
