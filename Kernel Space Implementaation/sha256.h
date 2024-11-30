// kernel/sha256.h
#ifndef SHA256_H
#define SHA256_H

#include "types.h"

#define SHA256_BLOCK_SIZE 32  // SHA256 outputs a 32 byte digest

// SHA-256 context
struct SHA256_CTX {
  uint8 data[64];
  uint datalen;
  uint bitlen[2];
  uint state[8];
};

void sha256_init(struct SHA256_CTX* ctx);
void sha256_update(struct SHA256_CTX* ctx, const uint8* data, uint len);
void sha256_final(struct SHA256_CTX* ctx, uint8 hash[]);

#endif
