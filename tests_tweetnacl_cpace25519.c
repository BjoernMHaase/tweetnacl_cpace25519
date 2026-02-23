// Written by B. Haase, Endress + Hauser Liquid Analysis
//
// Licensed under CC0 license. See tweetnacl_cpace25519.c for full license text.


#include "tweetnacl_cpace25519.h"
#include "tweetnacl_cpace25519_internal_api.h"

#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>

void randombytes(char *data, size_t len) {
  // We have this function only because otherwise the tests would not link.
  assert(0);
}

const unsigned char tc_PRS[] = {
    0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
};
const unsigned char tc_CI[] = {
    0x6f, 0x63, 0x0b, 0x42, 0x5f, 0x72, 0x65, 0x73, 0x70,
    0x6f, 0x6e, 0x64, 0x65, 0x72, 0x0b, 0x41, 0x5f, 0x69,
    0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72,
};
const unsigned char tc_sid[] = {
    0x7e, 0x4b, 0x47, 0x91, 0xd6, 0xa8, 0xef, 0x01,
    0x9b, 0x93, 0x6c, 0x79, 0xfb, 0x7f, 0x2c, 0x57,
};

const unsigned char tc_g[] = {
    0x64, 0xe8, 0x09, 0x9e, 0x3e, 0xa6, 0x82, 0xcf, 0xdc, 0x5c, 0xb6,
    0x65, 0xc0, 0x57, 0xeb, 0xb5, 0x14, 0xd0, 0x6b, 0xf2, 0x3e, 0xbc,
    0x9f, 0x74, 0x3b, 0x51, 0xb8, 0x22, 0x42, 0x32, 0x70, 0x74,
};

const unsigned char tc_ya[] = {
    0x21, 0xb4, 0xf4, 0xbd, 0x9e, 0x64, 0xed, 0x35, 0x5c, 0x3e, 0xb6,
    0x76, 0xa2, 0x8e, 0xbe, 0xda, 0xf6, 0xd8, 0xf1, 0x7b, 0xdc, 0x36,
    0x59, 0x95, 0xb3, 0x19, 0x09, 0x71, 0x53, 0x04, 0x40, 0x80,
};

const unsigned char tc_ADa[] = {
    0x41,
    0x44,
    0x61,
};

const unsigned char tc_Ya[] = {
    0x1b, 0x02, 0xda, 0xd6, 0xdb, 0xd2, 0x9a, 0x07, 0xb6, 0xd2, 0x8c,
    0x9e, 0x04, 0xcb, 0x2f, 0x18, 0x4f, 0x07, 0x34, 0x35, 0x0e, 0x32,
    0xbb, 0x7e, 0x62, 0xff, 0x9d, 0xbc, 0xfd, 0xb6, 0x3d, 0x15,
};

const unsigned char tc_yb[] = {
    0x84, 0x8b, 0x07, 0x79, 0xff, 0x41, 0x5f, 0x0a, 0xf4, 0xea, 0x14,
    0xdf, 0x9d, 0xd1, 0xd3, 0xc2, 0x9a, 0xc4, 0x1d, 0x83, 0x6c, 0x78,
    0x08, 0x89, 0x6c, 0x4e, 0xba, 0x19, 0xc5, 0x1a, 0xc4, 0x0a,
};

const unsigned char tc_ADb[] = {
    0x41,
    0x44,
    0x62,
};

const unsigned char tc_Yb[] = {
    0x20, 0xcd, 0xa5, 0x95, 0x5f, 0x82, 0xc4, 0x93, 0x15, 0x45, 0xbc,
    0xbf, 0x40, 0x75, 0x8c, 0xe1, 0x01, 0x0d, 0x7d, 0xb4, 0xdb, 0x2a,
    0x90, 0x70, 0x13, 0xd7, 0x9c, 0x7a, 0x8f, 0xcf, 0x95, 0x7f,
};

const unsigned char tc_K[] = {
    0xf9, 0x7f, 0xdf, 0xcf, 0xff, 0x1c, 0x98, 0x3e, 0xd6, 0x28, 0x38,
    0x56, 0xa4, 0x01, 0xde, 0x31, 0x91, 0xca, 0x91, 0x99, 0x02, 0xb3,
    0x23, 0xc5, 0xf9, 0x50, 0xc9, 0x70, 0x3d, 0xf7, 0x29, 0x7a,
};

const unsigned char tc_ISK_IR[] = {
    0xa0, 0x51, 0xee, 0x5e, 0xe2, 0x49, 0x9d, 0x16, 0xda, 0x3f, 0x69,
    0xf4, 0x30, 0x21, 0x8b, 0x8e, 0xa9, 0x4a, 0x18, 0xa4, 0x5b, 0x67,
    0xf9, 0xe8, 0x64, 0x95, 0xb3, 0x82, 0xc3, 0x3d, 0x14, 0xa5, 0xc3,
    0x8c, 0xec, 0xc0, 0xcc, 0x83, 0x4f, 0x96, 0x0e, 0x39, 0xe0, 0xd1,
    0xbf, 0x7d, 0x76, 0xb9, 0xef, 0x5d, 0x54, 0xee, 0xcc, 0x5e, 0x0f,
    0x38, 0x6c, 0x97, 0xad, 0x12, 0xda, 0x8c, 0x3d, 0x5f,
};

const unsigned char tc_ISK_SY[] = {
    0x5c, 0xc2, 0x7e, 0x49, 0x67, 0x94, 0x23, 0xf8, 0x1a, 0x37, 0xd7,
    0x52, 0x1d, 0x9f, 0xb1, 0x32, 0x7c, 0x84, 0x0d, 0x2e, 0xa4, 0xa1,
    0x54, 0x36, 0x52, 0xe7, 0xde, 0x5c, 0xab, 0xb8, 0x9e, 0xba, 0xd2,
    0x7d, 0x24, 0x76, 0x1b, 0x32, 0x88, 0xa3, 0xfd, 0x57, 0x64, 0xb4,
    0x41, 0xec, 0xb7, 0x8d, 0x30, 0xab, 0xc2, 0x61, 0x61, 0xff, 0x45,
    0xea, 0x29, 0x7b, 0xb3, 0x11, 0xdd, 0xe0, 0x47, 0x27,
};

int main(int argc, char **argv) {
  printf("Test for CPace25519 (both, symmetric and initiator-responder "
         "versions.\n\n");

  unsigned char storage[512];
  STBufferWithSize gen_string = {storage, 0u, sizeof(storage)};

  /* Example blobs */
  const unsigned char DSI[] = "CPace255";

  /* Build generator_string into out. Test internal function. Not part of the
   * public API*/
  if (!generator_string(&gen_string, DSI, sizeof(DSI) - 1, tc_PRS,
                        sizeof(tc_PRS), tc_CI, sizeof(tc_CI), tc_sid,
                        sizeof(tc_sid), 128u)) {
    /* handle overflow */
    printf("Buffer too small for calculating generator string.\n");
  } else {
    printf("Length of generator string: %i, expected: 172 bytes\n",
           gen_string.actualLen);
    for (int i = 0; i < gen_string.actualLen; i++) {
      printf("%02x", gen_string.data[i]);
    }
  }

  unsigned char storage_gen[512];
  STBufferWithSize gen_buffer = {storage_gen, 0u, sizeof(storage_gen)};

  if (!cpace25519_calculate_generator(&gen_buffer, tc_PRS, sizeof(tc_PRS),
                                      tc_CI, sizeof(tc_CI), tc_sid,
                                      sizeof(tc_sid))) {
    /* handle overflow */
    printf("\nBuffer too small for calculating generator.\n");
  } else {
    printf("\n\nLength of generator : %i, expected: 32 bytes\n",
           gen_buffer.actualLen);
    for (int i = 0; i < gen_buffer.actualLen; i++) {
      printf("%02x", gen_buffer.data[i]);
    }
  }

  if (memcmp(tc_g, &gen_buffer.data[0], 32) == 0) {
    printf("\nCorrect generator result.\n");
  } else {
    printf("\nWrong generator result.\n");
  }

  unsigned char Ya[32];
  crypto_scalarmult(Ya, tc_ya, gen_buffer.data);

  unsigned char Yb[32];
  crypto_scalarmult(Yb, tc_yb, gen_buffer.data);

  unsigned char K1[32];
  crypto_scalarmult(K1, tc_yb, Ya);

  unsigned char K2[32];
  crypto_scalarmult(K2, tc_yb, Ya);

  printf("\nCalculated K = g * ya:\n");
  for (int i = 0; i < 32; i++) {
    printf("%02x", K1[i]);
  }

  if ((memcmp(K1, K2, 32) == 0) && (memcmp(K1, tc_K, 32) == 0)) {
    printf("\nCorrect K result.\n");
  } else {
    printf("\nWrong K result.\n");
  }

  {
    unsigned char ISK_str_storage[512];
    STBufferWithSize isk_str = {ISK_str_storage, 0u, sizeof(ISK_str_storage)};
    unsigned char ISK_result[64];

    bool buffer_was_large_enough =
        ISK_string_ir(&isk_str, tc_sid, sizeof(tc_sid), K1, Ya, tc_ADa,
                      sizeof(tc_ADa), Yb, tc_ADb, sizeof(tc_ADb));

    if (!buffer_was_large_enough) {
      printf(
          "\nError. Test code buffer not large enough for holding ISK string.");
    }

    printf("\nLength of ISK_IR string: %i, expected: 137 bytes\n",
           isk_str.actualLen);
    for (int i = 0; i < isk_str.actualLen; i++) {
      printf("%02x", isk_str.data[i]);
    }

    buffer_was_large_enough =
        cpace25519_ISK_ir(&isk_str, tc_sid, sizeof(tc_sid), K1, Ya, tc_ADa,
                          sizeof(tc_ADa), Yb, tc_ADb, sizeof(tc_ADb));

    if (!buffer_was_large_enough) {
      printf("\nError. Test code buffer not large enough for ISK calculation.");
    }

    if ((memcmp(tc_ISK_IR, &isk_str.data[0], 64) == 0) &&
        (isk_str.actualLen == 64)) {
      printf("\n\nCorrect ISK_IR result.\n");
    } else {
      printf("\n\nWrong ISK_IR result.\n");
    }
    for (int i = 0; i < 64; i++) {
      printf("%02x", isk_str.data[i]);
    }
  }

  {
    unsigned char ISK_str_storage[512];
    STBufferWithSize isk_str = {ISK_str_storage, 0u, sizeof(ISK_str_storage)};
    unsigned char ISK_result[64];

    bool buffer_was_large_enough =
        ISK_string_oc(&isk_str, tc_sid, sizeof(tc_sid), K1, Ya, tc_ADa,
                      sizeof(tc_ADa), Yb, tc_ADb, sizeof(tc_ADb));

    if (!buffer_was_large_enough) {
      printf("\nError. Test code buffer not large enough for holding ISK "
             "string.\n");
    }

    printf("\n\nLength of ISK_OC string: %i, expected: 139 bytes\n",
           isk_str.actualLen);
    for (int i = 0; i < isk_str.actualLen; i++) {
      printf("%02x", isk_str.data[i]);
    }

    buffer_was_large_enough =
        cpace25519_ISK_sym(&isk_str, tc_sid, sizeof(tc_sid), K1, Ya, tc_ADa,
                           sizeof(tc_ADa), Yb, tc_ADb, sizeof(tc_ADb));

    if (!buffer_was_large_enough) {
      printf(
          "Error. Test code buffer not large enough for holding ISK string.");
    }

    if ((memcmp(tc_ISK_SY, &isk_str.data[0], 64) == 0) &&
        (isk_str.actualLen == 64)) {
      printf("\n\nCorrect ISK_OC result.\n");
    } else {
      printf("\n\nWrong ISK_OC result.\n");
    }
    for (int i = 0; i < 64; i++) {
      printf("%02x", isk_str.data[i]);
    }
  }
}