/* Derived from libtomcrypt implementation */

#ifndef _AES128_H_
#define _AES128_H_

#include <stdint.h>
#include <assert.h>

/* Macros declaration */

#define AES128_OK      0
#define AES128_NOK     1
#define BYTE(x, n) (((x) >> (8 * (n))) & 0xFF)
        
#if defined (__i386) || defined (__i386__) || defined (_M_IX86) || defined (INTEL_CC)

  #ifndef ENDIAN_LITTLE
    #define ENDIAN_LITTLE
  #endif
    #define ENDIAN_32BITWORD
    #define UNALIGNED

#elif defined (__alpha)

  #ifndef ENDIAN_LITTLE
    #define ENDIAN_LITTLE
  #endif
    #define ENDIAN_64BITWORD

#elif defined (__x86_64__)

  #ifndef ENDIAN_LITTLE
    #define ENDIAN_LITTLE
  #endif
    #define ENDIAN_64BITWORD
    #define UNALIGNED

#elif (defined (__R5900) || defined (R5900) || defined (__R5900__)) && (defined (_mips) || defined (__mips__) || defined (mips))

  #ifndef ENDIAN_LITTLE
    #define ENDIAN_LITTLE
  #endif
    #define ENDIAN_64BITWORD

#elif defined (__sparc)

  #ifndef ENDIAN_BIG
    #define ENDIAN_BIG
  #endif
    #if defined (__arch64__)
        #define ENDIAN_64BITWORD
    #else
        #define ENDIAN_32BITWORD
    #endif

#endif

#if !defined (ENDIAN_BIG) && !defined (ENDIAN_LITTLE)
    #error "Unknown endianness of the compilation platform, check this header aes128.h"
#endif

#ifdef ENDIAN_LITTLE

#if defined(INTEL_CC) || (defined(__GNUC__) && (defined(__DJGPP__) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__i386__) || defined(__x86_64__)))

    #define STORE32H(y, x) __asm__ __volatile__ ( \
        "bswapl %0     \n\t"                     \
        "movl   %0,(%2)\n\t"                     \
        "bswapl %0     \n\t"                     \
        :"=r"(x):"0"(x), "r"(y))

    #define LOAD32H(x, y) __asm__ __volatile__ (  \
        "movl (%2),%0\n\t"                       \
        "bswapl %0\n\t"                          \
        :"=r"(x): "0"(x), "r"(y))

#else

    #define STORE32H(y, x) {               \
        (y)[0] = (uint8_t)(((x) >>24) & 0xFF);  \
        (y)[1] = (uint8_t)(((x) >>16) & 0xFF);  \
        (y)[2] = (uint8_t)(((x) >> 8) & 0xFF);  \
        (y)[3] = (uint8_t)(((x) >> 0) & 0xFF);  \
    }
    #define LOAD32H(x, y) {                \
        x = ((uint32_t)((y)[0] & 0xFF) << 24) | \
            ((uint32_t)((y)[1] & 0xFF) << 16) | \
            ((uint32_t)((y)[2] & 0xFF) <<  8) | \
            ((uint32_t)((y)[3] & 0xFF) <<  0);  \
    }

#endif

#endif /* ENDIAN_LITTLE */

#ifdef ENDIAN_BIG

#define STORE32L(x, y) {                \
    (y)[3] = (uint8_t)(((x) >>24) & 0xFF); \
    (y)[2] = (uint8_t)(((x) >>16) & 0xFF); \
    (y)[1] = (uint8_t)(((x) >> 8) & 0xFF); \
    (y)[0] = (uint8_t)(((x) >> 0) & 0xFF); \
}

#define LOAD32L(x, y) {                  \
    x = ((uint32_t)((y)[3] & 0xFF) << 24) | \
        ((uint32_t)((y)[2] & 0xFF) << 16) | \
        ((uint32_t)((y)[1] & 0xFF) <<  8) | \
        ((uint32_t)((y)[0] & 0xFF) <<  0);  \
}

#endif /* ENDIAN_BIG */

#define TE0(x) PRECOMP_TE0[(x)]
#define TE1(x) PRECOMP_TE1[(x)]
#define TE2(x) PRECOMP_TE2[(x)]
#define TE3(x) PRECOMP_TE3[(x)]

#define TE4_0(x) PRECOMP_TE4_0[(x)]
#define TE4_1(x) PRECOMP_TE4_1[(x)]
#define TE4_2(x) PRECOMP_TE4_2[(x)]
#define TE4_3(x) PRECOMP_TE4_3[(x)]

#define TD0(x) PRECOMP_TD0[(x)]
#define TD1(x) PRECOMP_TD1[(x)]
#define TD2(x) PRECOMP_TD2[(x)]
#define TD3(x) PRECOMP_TD3[(x)]

#define TD4_0(x) (PRECOMP_TD4[(x)] & 0x000000FFUL)
#define TD4_1(x) (PRECOMP_TD4[(x)] & 0x0000FF00UL)
#define TD4_2(x) (PRECOMP_TD4[(x)] & 0x00FF0000UL)
#define TD4_3(x) (PRECOMP_TD4[(x)] & 0xFF000000UL)

#define TKS0(x) PRECOMP_TKS0[(x)]
#define TKS1(x) PRECOMP_TKS1[(x)]
#define TKS2(x) PRECOMP_TKS2[(x)]
#define TKS3(x) PRECOMP_TKS3[(x)]

        
void aes128_eks (uint32_t *ks, const uint8_t *k);
void aes128_dks (uint32_t *ks, const uint8_t *k);
void aes128_encrypt (uint8_t *c, const uint8_t *p, const uint32_t *ks);
void aes128_decrypt (uint8_t *p, const uint8_t *c, const uint32_t *ks);
            
/* Test code */

int test_aes128_eks ();
int test_aes128_dks ();
int test_aes128_encrypt ();
int test_aes128_decrypt ();

#endif /* _AES128_H_ */
