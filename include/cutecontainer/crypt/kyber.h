#ifndef CUTECONTAINER_CRYPT_KYBER_H
#define CUTECONTAINER_CRYPT_KYBER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ML-KEM-768 (Kyber-768) — NIST FIPS 203
 *
 * Post-quantum Key Encapsulation Mechanism based on Module-LWE.
 * Security level: roughly equivalent to AES-192 classical.
 */

#define CC_KYBER_PK_LEN        1184   /* Public key bytes  */
#define CC_KYBER_SK_LEN        2400   /* Secret key bytes  */
#define CC_KYBER_CT_LEN        1088   /* Ciphertext bytes  */
#define CC_KYBER_SS_LEN        32     /* Shared secret len */

#define CC_KYBER_N             256    /* Polynomial degree  */
#define CC_KYBER_K             3      /* Module rank (768)  */
#define CC_KYBER_Q             3329   /* Modulus             */

/*
 * Generate a Kyber keypair.
 * Returns 0 on success.
 */
int cc_kyber_keygen(
    uint8_t pk[CC_KYBER_PK_LEN],
    uint8_t sk[CC_KYBER_SK_LEN]
);

/*
 * Encapsulate: produce ciphertext + shared secret from a public key.
 * Returns 0 on success.
 */
int cc_kyber_encaps(
    const uint8_t pk[CC_KYBER_PK_LEN],
    uint8_t ct[CC_KYBER_CT_LEN],
    uint8_t ss[CC_KYBER_SS_LEN]
);

/*
 * Decapsulate: recover shared secret from ciphertext + secret key.
 * Returns 0 on success.
 */
int cc_kyber_decaps(
    const uint8_t sk[CC_KYBER_SK_LEN],
    const uint8_t ct[CC_KYBER_CT_LEN],
    uint8_t ss[CC_KYBER_SS_LEN]
);

/*
 * Low-level: forward NTT (Number Theoretic Transform) on a polynomial.
 * Operates in-place on 256 int16_t coefficients mod q=3329.
 * ASM implementations override this symbol.
 */
void cc_kyber_ntt(int16_t poly[CC_KYBER_N]);

/*
 * Low-level: inverse NTT.
 */
void cc_kyber_invntt(int16_t poly[CC_KYBER_N]);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_CRYPT_KYBER_H */
