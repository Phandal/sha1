#include "sha256.h"

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void _sha256_compress_block(sha256_ctx_t *ctx);
void _sha256_pad_block(sha256_ctx_t *ctx);

uint32_t _sha256_ch(uint32_t x, uint32_t y, uint32_t z);
uint32_t _sha256_maj(uint32_t x, uint32_t y, uint32_t z);
uint32_t _sha256_bsig0(uint32_t x);
uint32_t _sha256_bsig1(uint32_t x);
uint32_t _sha256_ssig0(uint32_t x);
uint32_t _sha256_ssig1(uint32_t x);

uint32_t _sha256_rotr(uint32_t x, uint32_t n);
uint32_t _sha256_shr(uint32_t x, uint32_t n);

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

sha256_err sha256_feed(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
  if (!ctx) {
    return SHA256_NULL;
  }

  if (ctx->digested) {
    return SHA256_CORRUPT;
  }

  for (size_t x = 0; x < len; ++x) {
    if (ctx->block_idx == SHA256_BLOCK_SIZE) {
      _sha256_compress_block(ctx);
    }

    ctx->block[ctx->block_idx++] = data[x];
    ctx->message_length += 8;

    // Integer Overflow
    if (ctx->message_length == 0) {
      return SHA256_SIZE;
    }
  }

  return SHA256_OK;
}

sha256_err sha256_digest(sha256_ctx_t *ctx, uint8_t digest[SHA256_HASH_SIZE]) {
  sha256_err err;
  if (!ctx) {
    return SHA256_NULL;
  }

  if (ctx->digested) {
    return SHA256_CORRUPT;
  }

  _sha256_pad_block(ctx);

  // Clear the block
  for (int x = 0; x < SHA256_BLOCK_SIZE; ++x) {
    ctx->block[x] = 0;
  }

  ctx->digested = 1;

  for (int i = 0; i < SHA256_HASH_SIZE / 4; ++i) {
    digest[i * 4] = ctx->hash[i] >> 24;
    digest[i * 4 + 1] = ctx->hash[i] >> 16;
    digest[i * 4 + 2] = ctx->hash[i] >> 8;
    digest[i * 4 + 3] = ctx->hash[i];
  }

  return SHA256_OK;
}

void _sha256_compress_block(sha256_ctx_t *ctx) {
  int i;
  uint32_t W[64];
  uint32_t temp1, temp2, a, b, c, d, e, f, g, h;

  for (i = 0; i < 16; ++i) {
    W[i] = (uint32_t)ctx->block[i * 4] << 24;
    W[i] |= (uint32_t)ctx->block[i * 4 + 1] << 16;
    W[i] |= (uint32_t)ctx->block[i * 4 + 2] << 8;
    W[i] |= (uint32_t)ctx->block[i * 4 + 3];
  }

  for (i = 16; i < 64; ++i) {
    W[i] = _sha256_ssig1(W[i - 2]) + W[i - 7] + _sha256_ssig0(W[i - 15]) +
           W[i - 16];
  }

  a = ctx->hash[0];
  b = ctx->hash[1];
  c = ctx->hash[2];
  d = ctx->hash[3];
  e = ctx->hash[4];
  f = ctx->hash[5];
  g = ctx->hash[6];
  h = ctx->hash[7];

  for (i = 0; i < 64; ++i) {
    temp1 = h + _sha256_bsig1(e) + _sha256_ch(e, f, g) + K[i] + W[i];
    temp2 = _sha256_bsig0(a) + _sha256_maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  ctx->hash[0] += a;
  ctx->hash[1] += b;
  ctx->hash[2] += c;
  ctx->hash[3] += d;
  ctx->hash[4] += e;
  ctx->hash[5] += f;
  ctx->hash[6] += g;
  ctx->hash[7] += h;

  ctx->block_idx = 0;
}

void _sha256_pad_block(sha256_ctx_t *ctx) {
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

    _sha256_compress_block(ctx);

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

  _sha256_compress_block(ctx);
}

uint32_t _sha256_ch(uint32_t x, uint32_t y, uint32_t z) {
  // CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
  return (x & y) ^ ((~x) & z);
}

uint32_t _sha256_maj(uint32_t x, uint32_t y, uint32_t z) {
  // MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
  return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t _sha256_bsig0(uint32_t x) {
  // BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
  return _sha256_rotr(x, 2) ^ _sha256_rotr(x, 13) ^ _sha256_rotr(x, 22);
}

uint32_t _sha256_bsig1(uint32_t x) {
  // BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
  return _sha256_rotr(x, 6) ^ _sha256_rotr(x, 11) ^ _sha256_rotr(x, 25);
}

uint32_t _sha256_ssig0(uint32_t x) {
  // SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
  return _sha256_rotr(x, 7) ^ _sha256_rotr(x, 18) ^ _sha256_shr(x, 3);
}

uint32_t _sha256_ssig1(uint32_t x) {
  // SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
  return _sha256_rotr(x, 17) ^ _sha256_rotr(x, 19) ^ _sha256_shr(x, 10);
}

uint32_t _sha256_rotr(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

uint32_t _sha256_shr(uint32_t x, uint32_t n) { return x >> n; }
