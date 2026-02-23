#ifndef CPACE_TWEETNACL_INTERNAL_
#define CPACE_TWEETNACL_INTERNAL_

#include "tweetnacl_cpace25519.h"

// Written by B. Haase, Endress + Hauser Liquid Analysis
//
// Licensed under CC0 license. See tweetnacl_cpace25519.c for full license text.

bool generator_string(STBufferWithSize *out, const unsigned char *DSI,
                      size_t DSI_len, const unsigned char *PRS, size_t PRS_len,
                      const unsigned char *CI, size_t CI_len,
                      const unsigned char *sid, size_t sid_len,
                      size_t s_in_bytes);

void decode_u_coor(unsigned char inout[crypto_scalarmult_curve25519_BYTES]);

void elligator2(unsigned char x_[crypto_scalarmult_curve25519_BYTES],
                const unsigned char r_[crypto_scalarmult_curve25519_BYTES]);

#ifdef CPACE_SYM

bool ISK_string_oc(STBufferWithSize *out, const unsigned char *sid,
                   size_t sid_len,
                   const unsigned char K[crypto_scalarmult_curve25519_BYTES],
                   const unsigned char Ya[crypto_scalarmult_curve25519_BYTES],
                   const unsigned char *ADa, size_t ADa_len,
                   const unsigned char Yb[crypto_scalarmult_curve25519_BYTES],
                   const unsigned char *ADb, size_t ADb_len);
#endif

#ifdef CPACE_IR

bool ISK_string_ir(STBufferWithSize *out, const unsigned char *sid,
                   size_t sid_len,
                   const unsigned char K[crypto_scalarmult_curve25519_BYTES],
                   const unsigned char Ya[crypto_scalarmult_curve25519_BYTES],
                   const unsigned char *ADa, size_t ADa_len,
                   const unsigned char Yb[crypto_scalarmult_curve25519_BYTES],
                   const unsigned char *ADb, size_t ADb_len);
#endif

#endif