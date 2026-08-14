#include <stdint.h>
#include <stdio.h>

typedef enum {
  SHA1_OK = 0,
  SHA1_NULL,
} sha1_err;

typedef struct {
  int block_idx;
  uint8_t block[64];
} sha1_ctx_t;

sha1_ctx_t *sha1_init();
sha1_err sha1_feed(sha1_ctx_t *ctx, uint8_t *data, size_t len);
sha1_err sha1_digest(sha1_ctx_t *ctx, uint8_t digest[20]);

int main(void) {
  sha1_err err;
  uint8_t digest[20];
  uint8_t data[3] = {'a', 'b', 'c'};

  sha1_ctx_t *ctx = sha1_init();
  if (!ctx) {
    fprintf(stderr, "Could not initialize sha1 context\n");
    return 1;
  }

  err = sha1_feed(ctx, data, 3);
  if (err != SHA1_OK) {
    fprintf(stderr, "sha1 feed error\n");
    return 1;
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
