#include "tweetnacl_cpace25519.h"

// Written by B. Haase, Endress + Hauser Liquid Analysis
//
// Licensed under CC0 license. See full license text below.

/*

CC0 1.0 Universal
CREATIVE COMMONS CORPORATION IS NOT A LAW FIRM AND DOES NOT PROVIDE LEGAL SERVICES. 
DISTRIBUTION OF THIS DOCUMENT DOES NOT CREATE AN ATTORNEY-CLIENT RELATIONSHIP. 
CREATIVE COMMONS PROVIDES THIS INFORMATION ON AN "AS-IS" BASIS. CREATIVE COMMONS MAKES NO
WARRANTIES REGARDING THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS PROVIDED HEREUNDER, 
AND DISCLAIMS LIABILITY FOR DAMAGES RESULTING FROM THE USE OF THIS DOCUMENT OR THE 
INFORMATION OR WORKS PROVIDED HEREUNDER.

Statement of Purpose
The laws of most jurisdictions throughout the world automatically confer exclusive Copyright and 
Related Rights (defined below) upon the creator and subsequent owner(s) (each and all, an "owner") 
of an original work of authorship and/or a database (each, a "Work").

Certain owners wish to permanently relinquish those rights to a Work for the purpose of contributing 
to a commons of creative, cultural and scientific works ("Commons") that the public can reliably and 
without fear of later claims of infringement build upon, modify, incorporate in other works, reuse and
redistribute as freely as possible in any form whatsoever and for any purposes, including without
limitation commercial purposes. These owners may contribute to the Commons to promote the ideal of a
free culture and the further production of creative, cultural and scientific works, or to gain reputation
or greater distribution for their Work in part through the use and efforts of others.

For these and/or other purposes and motivations, and without any expectation of additional consideration
or compensation, the person associating CC0 with a Work (the "Affirmer"), to the extent that he or she
is an owner of Copyright and Related Rights in the Work, voluntarily elects to apply CC0 to the Work and 
publicly distribute the Work under its terms, with knowledge of his or her Copyright and Related Rights 
in the Work and the meaning and intended legal effect of CC0 on those rights.

1. Copyright and Related Rights.
A Work made available under CC0 may be protected by copyright and related or neighboring rights 
("Copyright and Related Rights"). Copyright and Related Rights include, but are not limited 
to, the following:

the right to reproduce, adapt, distribute, perform, display, communicate, and translate a Work;
moral rights retained by the original author(s) and/or performer(s);
publicity and privacy rights pertaining to a person's image or likeness depicted in a Work;
rights protecting against unfair competition in regards to a Work, subject to the limitations in paragraph 4(a), below;
rights protecting the extraction, dissemination, use and reuse of data in a Work;
database rights (such as those arising under Directive 96/9/EC of the European Parliament and of the Council 
of 11 March 1996 on the legal protection of databases, and under any national implementation thereof, including
any amended or successor version of such directive); and
other similar, equivalent or corresponding rights throughout the world based on applicable law or treaty, and any 
national implementations thereof.

2. Waiver.
To the greatest extent permitted by, but not in contravention of, applicable law, Affirmer hereby overtly, fully, 
permanently, irrevocably and unconditionally waives, abandons, and surrenders all of Affirmer's Copyright and 
Related Rights and associated claims and causes of action, whether now known or unknown (including existing as 
well as future claims and causes of action), in the Work (i) in all territories worldwide, (ii) for the maximum 
duration provided by applicable law or treaty (including future time extensions), (iii) in any current or future 
medium and for any number of copies, and (iv) for any purpose whatsoever, including without limitation commercial, 
advertising or promotional purposes (the "Waiver"). Affirmer makes the Waiver for the benefit of each member of the 
public at large and to the detriment of Affirmer's heirs and successors, fully intending that such Waiver shall not 
be subject to revocation, rescission, cancellation, termination, or any other legal or equitable action to disrupt 
the quiet enjoyment of the Work by the public as contemplated by Affirmer's express Statement of Purpose.

3. Public License Fallback.
Should any part of the Waiver for any reason be judged legally invalid or ineffective under applicable law, then the 
Waiver shall be preserved to the maximum extent permitted taking into account Affirmer's express Statement of Purpose. 
In addition, to the extent the Waiver is so judged Affirmer hereby grants to each affected person a royalty-free, non 
transferable, non sublicensable, non exclusive, irrevocable and unconditional license to exercise Affirmer's Copyright 
and Related Rights in the Work (i) in all territories worldwide, (ii) for the maximum duration provided by applicable 
law or treaty (including future time extensions), (iii) in any current or future medium and for any number of copies, 
and (iv) for any purpose whatsoever, including without limitation commercial, advertising or promotional purposes 
(the "License"). The License shall be deemed effective as of the date CC0 was applied by Affirmer to the Work. 
Should any part of the License for any reason be judged legally invalid or ineffective under applicable law, such 
partial invalidity or ineffectiveness shall not invalidate the remainder of the License, and in such case Affirmer 
hereby affirms that he or she will not (i) exercise any of his or her remaining Copyright and Related Rights in the
Work or (ii) assert any associated claims and causes of action with respect to the Work, in either case contrary to 
Affirmer's express Statement of Purpose.

4. Limitations and Disclaimers.
No trademark or patent rights held by Affirmer are waived, abandoned, surrendered, licensed or otherwise affected 
by this document.
Affirmer offers the Work as-is and makes no representations or warranties of any kind concerning the Work, express, 
implied, statutory or otherwise, including without limitation warranties of title, merchantability, fitness for a 
particular purpose, non infringement, or the absence of latent or other defects, accuracy, or the present or absence 
of errors, whether or not discoverable, all to the greatest extent permissible under applicable law.
Affirmer disclaims responsibility for clearing rights of other persons that may apply to the Work or any use thereof, 
including without limitation any person's Copyright and Related Rights in the Work. Further, Affirmer disclaims 
responsibility for obtaining any necessary consents, permissions or other rights required for any use of the Work.
Affirmer understands and acknowledges that Creative Commons is not a party to this document and has no duty or 
obligation with respect to this CC0 or use of the Work.

*/

// We need all of the internal static functions of tweetnacl.c so we include the full file here.
#include "tweetnacl/tweetnacl.c_original"

#include <stddef.h>
#include <stdbool.h>
#include <string.h>

void decode_u_coor(unsigned char inout[crypto_scalarmult_curve25519_BYTES])
{
	inout[31] &= 0x7f;
}

static const char fe25519_one [crypto_scalarmult_curve25519_BYTES] = 
{ 
    1,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0
};

static const char fe25519_minusA [crypto_scalarmult_curve25519_BYTES] = 
{ 
    0xe7,0x92,0xf8,0xff, 0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0x7f    
};

static const char fe25519_minusAdiv2 [crypto_scalarmult_curve25519_BYTES] = 
{ 
    0x6a,0x49,0xfc,0xff, 0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0x7f
};

static const char fe25519_Asquare [crypto_scalarmult_curve25519_BYTES] = 
{ 
    0x11,0x1c,0xc2,0x24, 0x37,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x80    
};

// s = (c.d^2)^((p-3)/2)
static void elligator2s(gf *r, const gf *x)
{   
    pow2523(*r,*x);
	
    // r is now x ^ (2^252 - 3)
    S(*r, *r);
    // r is now x ^ (2^253 - 6)
    S(*r, *r);
    // r is now x ^ (2^254 - 12)
    M(*r, *r, *x);
    // r is now x ^ (2^254 - 11)
}

static void elligator2(
    unsigned char x_[crypto_scalarmult_curve25519_BYTES],
    const unsigned char  r_[crypto_scalarmult_curve25519_BYTES]
    )
{
    // Optimization using inverse square root trick.
    gf r; unpack25519(r, r_);

    // constants
    gf gf_one;        unpack25519(gf_one,        fe25519_one);
    gf gf_Asquare;    unpack25519(gf_Asquare,    fe25519_Asquare);
    gf gf_minusA;     unpack25519(gf_minusA,     fe25519_minusA);
    gf gf_minusAdiv2; unpack25519(gf_minusAdiv2, fe25519_minusAdiv2);

    // Scratch buffers
    gf t0;
    gf t1;
    gf t2;
    gf t3;
    gf v;
    gf x;

    // dead: x, t0, t1, t2, t3, v
    S(v, r);           // v = [r]^2                       (was d)
    A(t0, v, v);       // t0 = [r^2] + [r^2]
    A(v, t0, gf_one);  // v = 1 + [2.r^2]                 (was d)

    // dead: x, t1, t2, t3
    M(t2, gf_Asquare, t0); // t2 = [A^2] * [2.r^2]
    // dead: x, t0, t1, t3
    S(t1, v);              // t1 = [v]^2 = [d]^2
    // dead: x, t0, t3
    Z(t0, t1, t2);         // t0 = [d^2] - [(A^2).2.r^2]
    // dead: x, t2, t3
    M(t2, t0, gf_minusA);  // t2 = [-A] * [(d^2 - (A^2).2.r^2)]   (was a)
    // dead: x, t0, t3
    M(t0, v, t1);          // t0 = [d] * [d^2] = (1 + 2.r^2)^3     (was b, note reuse)
    // dead: x, t1, t3

    M(t3, t2, t0);         // t3 = [a] * [b]                       (was c)
    // dead: x, t0, t1, t2

    // x = (t3.v^2)^((p-3)/2) with p = 2^255 - 19 -> (p-3)/2 = 2^254 - 11
    M(t2, t3, v);          // t2 = [t3] * [v] = [c] * [d]
    // dead: x, t0, t1, t3
    M(v, v, t2);           // v = c.d^2 = [c.d] * [d]
    // dead: x, t0, t1, t3

    elligator2s(&x, &v);   // x plays role of s, v is c.d^2

    // dead: t0, t1, t3
    M(t0, x, v);           // t0 = epsilon = [s] * [c.d^2]         (eps reuses t0)
    // dead: t1, t3, v
    // 1/d = s.epsilon.c.d
    M(t3, x, t0);          // t3 = [s] * [epsilon]
    // dead: x, t1, v
    M(t1, t3, t2);         // t1 = [s.epsilon] * [c.d] = 1/d
    // dead: x, t2, t3, v

    M(v, t1, gf_minusA);   // v = -A/(1 + 2.r^2) = [-A] * [1/d]
    // dead: x, t1, t2, t3

    Z(t1, gf_one, t0);     // t1 = 1 - [epsilon]
    // dead: x, t0, t2, t3
    M(t2, t0, v);          // t2 = [epsilon] * [v]
    // dead: x, t0, t3, v
    M(t3, gf_minusAdiv2, t1); // t3 = [-A/2] * [1 - epsilon]
    // dead: x, t0, t1, v
    A(x, t2, t3);          // x = [epsilon.v] + [-A/2.(1 - epsilon)]
    // dead: t0, t1, t2, t3, v
    pack25519(x_, x);
}

/* Append a single byte. Returns true on success, false on overflow. */
static bool append_byte(STBufferWithSize *buf, unsigned char byte)
{
    if (buf == NULL || buf->data == NULL) return false;

    if (buf->actualLen < buf->maxSize) {
        buf->data[buf->actualLen++] = byte;
        return true;
    }
    return false;
}

/* Append raw bytes. Returns true on success, false on overflow. */
static bool append_bytes(STBufferWithSize *buf,
                         const unsigned char *src,
                         size_t len)
{
    size_t i;
    if (len == 0) return true;
    if (buf == NULL || buf->data == NULL) return false;
    if (src == NULL) return false;

    /* overflow check */
    if (buf->actualLen > buf->maxSize) return false;
    if (len > (buf->maxSize - buf->actualLen)) return false;

    /* ANSI-C compatible copy loop (avoid assuming memmove availability is fine too) */
    for (i = 0; i < len; i++) {
        buf->data[buf->actualLen + i] = src[i];
    }
    buf->actualLen += len;
    return true;
}

/* Append N zero bytes. Returns true on success, false on overflow. */
static bool append_zeros(STBufferWithSize *buf, size_t n)
{
    size_t i;
    if (n == 0) return true;
    if (buf == NULL || buf->data == NULL) return false;

    if (buf->actualLen > buf->maxSize) return false;
    if (n > (buf->maxSize - buf->actualLen)) return false;

    for (i = 0; i < n; i++) {
        buf->data[buf->actualLen + i] = 0u;
    }
    buf->actualLen += n;
    return true;
}

/* Compute how many bytes ULEB128 encoding of value uses. */
static size_t uleb128_size(size_t value)
{
    size_t n = 0;
    do {
        n++;
        value >>= 7;
    } while (value != 0);
    return n;
}

/* Append ULEB128(value) to buffer. Returns true on success. */
static bool append_uleb128(STBufferWithSize *out, size_t value)
{
    while (1) {
        unsigned char byte = (unsigned char)(value & 0x7Fu);
        value >>= 7;
        if (value != 0) {
            byte = (unsigned char)(byte | 0x80u);
        }
        if (!append_byte(out, byte)) return false;
        if (value == 0) break;
    }
    return true;
}

/* Equivalent to Python prepend_len(data): write LEB128(len) then data. */
static bool prepend_len_append(STBufferWithSize *out,
                               const unsigned char *data,
                               size_t dataLen)
{
    if (!append_uleb128(out, dataLen)) return false;
    if (dataLen == 0) return true;
    return append_bytes(out, data, dataLen);
}

/* Like prepend_len, but the payload is N zero bytes (no temp allocation). */
static bool prepend_len_append_zeros(STBufferWithSize *out,
                                     size_t zerosLen)
{
    if (!append_uleb128(out, zerosLen)) return false;
    return append_zeros(out, zerosLen);
}

static size_t prepend_len_total_size(size_t payloadLen)
{
    return uleb128_size(payloadLen) + payloadLen;
}

// External API
bool generator_string(STBufferWithSize *out,
                      const unsigned char *DSI, size_t DSI_len,
                      const unsigned char *PRS, size_t PRS_len,
                      const unsigned char *CI,  size_t CI_len,
                      const unsigned char *sid, size_t sid_len,
                      size_t s_in_bytes)
{
    size_t prs_total = prepend_len_total_size(PRS_len);
    size_t dsi_total = prepend_len_total_size(DSI_len);
    size_t len_zpad = 0;

    /* Python: max(0, s_in_bytes - 1 - prs_total - dsi_total) */
    if (s_in_bytes > 0) {
        size_t base = s_in_bytes - 1;
        if (base > prs_total && (base - prs_total) > dsi_total) {
            len_zpad = base - prs_total - dsi_total;
        } else {
            len_zpad = 0;
        }
    }

    /* lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid) */
    if (!prepend_len_append(out, DSI, DSI_len)) return false;
    if (!prepend_len_append(out, PRS, PRS_len)) return false;
    if (!prepend_len_append_zeros(out, len_zpad)) return false;
    if (!prepend_len_append(out, CI, CI_len)) return false;
    if (!prepend_len_append(out, sid, sid_len)) return false;

    return true;
}

bool cpace25519_calculate_generator(STBufferWithSize *out,
                      const unsigned char *PRS, size_t PRS_len,
                      const unsigned char *CI,  size_t CI_len,
                      const unsigned char *sid, size_t sid_len)
{
	out->actualLen = 0;
	const char DSI [] = "CPace255";

	if ((!generator_string(out, DSI, sizeof(DSI) - 1, PRS, PRS_len, CI, CI_len, sid, sid_len,128))
	   || (out->maxSize < 64) )
	{
		out->actualLen = 0;
		return false;
	}
	else
	{
		crypto_hash_sha512(&out->data[0], &out->data[0], out->actualLen);
		decode_u_coor(&out->data[0]);
		elligator2(&out->data[0],&out->data[0]);
		out->actualLen = 32;

		return true;
	}

}

#ifdef CPACE_IR

bool transcript_ir(STBufferWithSize *out,
                   const unsigned char *Ya,  size_t Ya_len,
                   const unsigned char *ADa, size_t ADa_len,
                   const unsigned char *Yb,  size_t Yb_len,
                   const unsigned char *ADb, size_t ADb_len)
{
    if (!prepend_len_append(out, Ya,  Ya_len))  return false;
    if (!prepend_len_append(out, ADa, ADa_len)) return false;
    if (!prepend_len_append(out, Yb,  Yb_len))  return false;
    if (!prepend_len_append(out, ADb, ADb_len)) return false;
    return true;
}

bool ISK_string_ir(STBufferWithSize *out,
                const unsigned char *sid, size_t sid_len,
                const unsigned char K[crypto_scalarmult_curve25519_BYTES],
				const unsigned char Ya[crypto_scalarmult_curve25519_BYTES],
                const unsigned char *ADa, size_t ADa_len,
                const unsigned char Yb[crypto_scalarmult_curve25519_BYTES],
                const unsigned char *ADb, size_t ADb_len
				)
{
    if (!prepend_len_append(out, "CPace255_ISK", 12)) return false;

    /* prepend_len(sid), prepend_len(K) */
    if (!prepend_len_append(out, sid, sid_len)) return false;
    if (!prepend_len_append(out, K,   crypto_scalarmult_curve25519_BYTES))   return false;

    return transcript_ir(out, Ya, crypto_scalarmult_curve25519_BYTES, ADa, ADa_len, Yb, crypto_scalarmult_curve25519_BYTES, ADb, ADb_len);
}

bool cpace25519_ISK_ir(STBufferWithSize *out,
            const unsigned char *sid, size_t sid_len,
            const unsigned char K[crypto_scalarmult_curve25519_BYTES], // length 32 
			const unsigned char Ya[crypto_scalarmult_curve25519_BYTES], // length 32
            const unsigned char *ADa, size_t ADa_len,
            const unsigned char Yb[crypto_scalarmult_curve25519_BYTES], // length 32
            const unsigned char *ADb, size_t ADb_len
			)
{
	out->actualLen = 0;
	
    if (!ISK_string_ir(out, sid, sid_len, K, Ya,  ADa, ADa_len, Yb, ADb, ADb_len)
	   || (out->maxSize < 64)
       || cpace25519_need_to_abort_on_invalid_K(K)
	   )
	{
		randombytes(out->data, out->maxSize); // fill with random values for safety
		out->actualLen = 0;
		return false;
	}
	else
	{
		crypto_hash_sha512(&out->data[0], &out->data[0], out->actualLen);
		out->actualLen = 64;
		return true;
	}
}

#endif // ifdef CPACE_IR

#ifdef CPACE_SYM

#warning "String ordering for oc_ functions not yet fully covered in tests."

/* --- helpers: byte-stream cursor for lv_cat( X1, X2 ) without building it --- */

typedef struct {
    /* inputs */
    const unsigned char *x1; size_t x1_len;
    const unsigned char *x2; size_t x2_len;

    /* state machine */
    unsigned phase;          /* 0: leb(x1)  1: x1  2: leb(x2)  3: x2  4: end */
    size_t idx;              /* index into x1/x2 when in data phases */
    size_t tmp;              /* shifting copy for leb generation */
} STLv2Cursor;

/* init cursor for stream = uleb128(x1_len)||x1||uleb128(x2_len)||x2 */
static void lv2cursor_init(STLv2Cursor *c,
                           const unsigned char *x1, size_t x1_len,
                           const unsigned char *x2, size_t x2_len)
{
    c->x1 = x1; c->x1_len = x1_len;
    c->x2 = x2; c->x2_len = x2_len;
    c->phase = 0u;
    c->idx = 0u;
    c->tmp = x1_len; /* used for leb(x1_len) first */
}

/* returns true and sets *out_byte if a byte is produced; false when end reached */
static bool lv2cursor_next(STLv2Cursor *c, unsigned char *out_byte)
{
    while (1) {
        switch (c->phase) {
        case 0: /* leb(x1_len) */
        {
            /* emit one ULEB128 byte of c->tmp */
            unsigned char b = (unsigned char)(c->tmp & 0x7Fu);
            c->tmp >>= 7;
            if (c->tmp != 0) b = (unsigned char)(b | 0x80u);
            *out_byte = b;

            if (c->tmp == 0) {
                c->phase = 1u;
                c->idx = 0u;
            }
            return true;
        }

        case 1: /* x1 */
            if (c->idx < c->x1_len) {
                *out_byte = c->x1[c->idx++];
                return true;
            }
            c->phase = 2u;
            c->tmp = c->x2_len;
            /* fallthrough */

        case 2: /* leb(x2_len) */
        {
            unsigned char b2 = (unsigned char)(c->tmp & 0x7Fu);
            c->tmp >>= 7;
            if (c->tmp != 0) b2 = (unsigned char)(b2 | 0x80u);
            *out_byte = b2;

            if (c->tmp == 0) {
                c->phase = 3u;
                c->idx = 0u;
            }
            return true;
        }

        case 3: /* x2 */
            if (c->idx < c->x2_len) {
                *out_byte = c->x2[c->idx++];
                return true;
            }
            c->phase = 4u;
            /* fallthrough */

        default: /* 4: end */
            return false;
        }
    }
}

/* Lexicographic compare of two lv_cat(.,.) streams:
   returns +1 if A>B, 0 if A==B, -1 if A<B
*/
static int lexcmp_lvcat2(const unsigned char *a1, size_t a1_len,
                         const unsigned char *a2, size_t a2_len,
                         const unsigned char *b1, size_t b1_len,
                         const unsigned char *b2, size_t b2_len)
{
    STLv2Cursor ca, cb;
    unsigned char ba = 0, bb = 0;
    bool ha, hb;

    lv2cursor_init(&ca, a1, a1_len, a2, a2_len);
    lv2cursor_init(&cb, b1, b1_len, b2, b2_len);

    while (1) {
        ha = lv2cursor_next(&ca, &ba);
        hb = lv2cursor_next(&cb, &bb);

        if (!ha && !hb) return 0;    /* equal */
        if (!ha && hb)  return -1;   /* A ended first -> smaller */
        if (ha && !hb)  return +1;   /* B ended first -> A larger */

        if (ba < bb) return -1;
        if (ba > bb) return +1;
        /* else equal byte: continue */
    }
}

bool transcript_oc(STBufferWithSize *out,
                   const unsigned char *Ya,  size_t Ya_len,
                   const unsigned char *ADa, size_t ADa_len,
                   const unsigned char *Yb,  size_t Yb_len,
                   const unsigned char *ADb, size_t ADb_len)
{
    /* Compare A=lv_cat(Ya,ADa) vs B=lv_cat(Yb,ADb) lexicographically */
    int cmp = lexcmp_lvcat2(Ya, Ya_len, ADa, ADa_len,
                            Yb, Yb_len, ADb, ADb_len);

    /* Emit: b"oc" + (larger first) + (smaller second) */
    if (!append_byte(out, (unsigned char)'o')) return false;
    if (!append_byte(out, (unsigned char)'c')) return false;

    if (cmp > 0) {
        /* A > B: "oc" || A || B */
        if (!prepend_len_append(out, Ya,  Ya_len))  return false;
        if (!prepend_len_append(out, ADa, ADa_len)) return false;

        if (!prepend_len_append(out, Yb,  Yb_len))  return false;
        if (!prepend_len_append(out, ADb, ADb_len)) return false;
    } else {
        /* A <= B: "oc" || B || A  (matches Python else branch) */
        if (!prepend_len_append(out, Yb,  Yb_len))  return false;
        if (!prepend_len_append(out, ADb, ADb_len)) return false;

        if (!prepend_len_append(out, Ya,  Ya_len))  return false;
        if (!prepend_len_append(out, ADa, ADa_len)) return false;
    }

    return true;
}

bool ISK_string_oc(STBufferWithSize *out,
                const unsigned char *sid, size_t sid_len,
                const unsigned char K[crypto_scalarmult_curve25519_BYTES],
				const unsigned char Ya[crypto_scalarmult_curve25519_BYTES],
                const unsigned char *ADa, size_t ADa_len,
                const unsigned char Yb[crypto_scalarmult_curve25519_BYTES],
                const unsigned char *ADb, size_t ADb_len
				)
{
    if (!prepend_len_append(out, "CPace255_ISK", 12)) return false;

    /* prepend_len(sid), prepend_len(K) */
    if (!prepend_len_append(out, sid, sid_len)) return false;
    if (!prepend_len_append(out, K, crypto_scalarmult_curve25519_BYTES))   return false;

    return transcript_oc(out, Ya, crypto_scalarmult_curve25519_BYTES, ADa, ADa_len, Yb, crypto_scalarmult_curve25519_BYTES, ADb, ADb_len);
}

bool cpace25519_ISK_sym(STBufferWithSize *out,
                const unsigned char *sid, size_t sid_len,
                const unsigned char K[crypto_scalarmult_curve25519_BYTES],
				const unsigned char Ya[crypto_scalarmult_curve25519_BYTES],
                const unsigned char *ADa, size_t ADa_len,
                const unsigned char Yb[crypto_scalarmult_curve25519_BYTES],
                const unsigned char *ADb, size_t ADb_len
				)
{
	out->actualLen = 0;
	
    if (!ISK_string_oc(out, sid, sid_len, K, Ya, ADa, ADa_len, Yb, ADb, ADb_len)
	   || (out->maxSize < 64)
       || cpace25519_need_to_abort_on_invalid_K(K)
	   )
	{
		randombytes(out->data, out->maxSize); // fill with random values for safety
		out->actualLen = 0;
		return false;
	}
	else
	{
		crypto_hash_sha512(&out->data[0], &out->data[0], out->actualLen);
		out->actualLen = 64;
		return true;
	}
}

#endif // ifdef CPACE_SY
