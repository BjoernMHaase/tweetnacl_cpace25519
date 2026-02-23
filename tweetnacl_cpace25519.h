#ifndef _CPACE25519_INCLUDE_GUARD
#define _CPACE25519_INCLUDE_GUARD

// Written by B. Haase, Endress + Hauser Liquid Analysis
//
// Licensed under CC0 license. See tweetnacl_cpace25519.c for full license text.

#include "tweetnacl/tweetnacl.h_original"
#include <memory.h>

/* Simple byte buffer type with overflow management.
   A structure of this type needs to be passed to the functions below with
   sufficient size.

   The maximum size of the data buffer needs to be configured in the maxSize
   parameter before any call to the library.
*/
typedef struct STBufferWithSize {
  unsigned char *data;
  size_t actualLen;
  size_t maxSize;
} STBufferWithSize;

// Return false if the buffer was not large enough for holding temporary data.
bool cpace25519_calculate_generator(STBufferWithSize *working_and_result_buffer,
                                    const unsigned char *PRS, size_t PRS_len,
                                    const unsigned char *CI, size_t CI_len,
                                    const unsigned char *sid, size_t sid_len);

// Note:
// use "crypto_scalarmult(Ya, ya, g);" and "crypto_scalarmult(Yb, yb, g);" for
// calculating Ya and Yb.

// Check calculated K after scalarmult calculation.
static bool cpace25519_need_to_abort_on_invalid_K(
    const unsigned char K[crypto_scalarmult_curve25519_BYTES]) {
  unsigned char check = 0;
  for (int i = 0; i < crypto_scalarmult_curve25519_BYTES; i++) {
    check |= K[i];
  }
  return (check == 0);
}

// Depending on your use: define either CPACE_SYM or CPACE_IR in your build
// environment e.g. use the "-DCPACE_IR" compile switch when using GCC.

#ifdef CPACE_SYM

// Return false if the buffer was not large enough for holding temporary data.
bool cpace25519_ISK_sym(
    STBufferWithSize *working_and_result_buffer, const unsigned char *sid,
    size_t sid_len, const unsigned char K[crypto_scalarmult_curve25519_BYTES],
    const unsigned char Ya[crypto_scalarmult_curve25519_BYTES],
    const unsigned char *ADa, size_t ADa_len,
    const unsigned char Yb[crypto_scalarmult_curve25519_BYTES],
    const unsigned char *ADb, size_t ADb_len);

#endif

#ifdef CPACE_IR

// Return false if the buffer was not large enough for holding temporary data.
bool cpace25519_ISK_ir(
    STBufferWithSize *working_and_result_buffer, const unsigned char *sid,
    size_t sid_len, const unsigned char K[crypto_scalarmult_curve25519_BYTES],
    const unsigned char Ya[crypto_scalarmult_curve25519_BYTES],
    const unsigned char *ADa, size_t ADa_len,
    const unsigned char Yb[crypto_scalarmult_curve25519_BYTES],
    const unsigned char *ADb, size_t ADb_len);

#endif

#endif
