#include "sha1.h"

sha1_err sha1_init(sha1_ctx_t *ctx) {
  if (!ctx) {
    return SHA1_NULL;
  }

  ctx->block_idx = 0;
  ctx->message_length = 0;

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
    ctx->message_length += 8;

    // Integer Overflow
    if (ctx->message_length == 0) {
      return SHA1_SIZE;
    }
  }

  return SHA1_OK;
}

sha1_err sha1_digest(sha1_ctx_t *ctx, uint8_t digest[20]) {
  if (!ctx) {
    return SHA1_NULL;
  }

  _sha1_pad_block(ctx);

  for (int i = 0; i < 5; ++i) {
    digest[i * 4] = ctx->hash[i] >> 24;
    digest[i * 4 + 1] = ctx->hash[i] >> 16;
    digest[i * 4 + 2] = ctx->hash[i] >> 8;
    digest[i * 4 + 3] = ctx->hash[i];
  }

  return SHA1_OK;
}

sha1_err _sha1_compress_block(sha1_ctx_t *ctx) {
  uint32_t K[4] = {0X5A827999, 0X6ED9EBA1, 0X8F1BBCDC, 0XCA62C1D6};
  uint32_t W[80];
  int i;
  uint32_t temp, a, b, c, d, e;

  // 1. expand the block into an array of 80 words
  // Load the first 1n words into the W array
  for (i = 0; i < 16; ++i) {
    W[i] = (uint32_t)ctx->block[i * 4] << 24;
    W[i] |= (uint32_t)ctx->block[i * 4 + 1] << 16;
    W[i] |= (uint32_t)ctx->block[i * 4 + 2] << 8;
    W[i] |= (uint32_t)ctx->block[i * 4 + 3];
  }

  // Load the rest of the words in the W array with a formula
  // W[i] = ROTL(W[i-3] XOR W[i-8] XOR W[i-14] XOR W[i-16], 1)
  for (i = 16; i < 80; ++i) {
    W[i] = _sha1_rotate(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
  }

  // 2. Setup the initial working vars
  a = ctx->hash[0];
  b = ctx->hash[1];
  c = ctx->hash[2];
  d = ctx->hash[3];
  e = ctx->hash[4];

  // 3. Run 80 rounds of compression on the word array
  for (i = 0; i < 20; ++i) {
    temp = _sha1_rotate(a, 5) + ((b & c) | ((~b) & d)) + e + W[i] + K[0];
    e = d;
    d = c;
    c = _sha1_rotate(b, 30);
    b = a;
    a = temp;
  }

  for (i = 20; i < 40; ++i) {
    temp = _sha1_rotate(a, 5) + (b ^ c ^ d) + e + W[i] + K[1];
    e = d;
    d = c;
    c = _sha1_rotate(b, 30);
    b = a;
    a = temp;
  }

  for (i = 40; i < 60; ++i) {
    temp = _sha1_rotate(a, 5) + ((b & c) | (b & d) | (c & d)) + e + W[i] + K[2];
    e = d;
    d = c;
    c = _sha1_rotate(b, 30);
    b = a;
    a = temp;
  }

  for (i = 60; i < 80; ++i) {
    temp = _sha1_rotate(a, 5) + (b ^ c ^ d) + e + W[i] + K[3];
    e = d;
    d = c;
    c = _sha1_rotate(b, 30);
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

uint32_t _sha1_rotate(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

sha1_err _sha1_pad_block(sha1_ctx_t *ctx) {
  if (ctx->block_idx < 55) {
    ctx->block[ctx->block_idx++] = 0x80;

    while (ctx->block_idx < 56) {
      ctx->block[ctx->block_idx++] = 0;
    }
  } else {
    ctx->block[ctx->block_idx++] = 0x80;

    while (ctx->block_idx < 64) {
      ctx->block[ctx->block_idx++] = 0;
    }

    _sha1_compress_block(ctx);

    while (ctx->block_idx < 56) {
      ctx->block[ctx->block_idx++] = 0;
    }
  }

  ctx->block[ctx->block_idx++] = ctx->message_length >> 56;
  ctx->block[ctx->block_idx++] = ctx->message_length >> 48;
  ctx->block[ctx->block_idx++] = ctx->message_length >> 40;
  ctx->block[ctx->block_idx++] = ctx->message_length >> 32;
  ctx->block[ctx->block_idx++] = ctx->message_length >> 24;
  ctx->block[ctx->block_idx++] = ctx->message_length >> 16;
  ctx->block[ctx->block_idx++] = ctx->message_length >> 8;
  ctx->block[ctx->block_idx++] = ctx->message_length;

  _sha1_compress_block(ctx);

  return SHA1_OK;
}
