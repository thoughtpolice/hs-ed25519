#include <string.h>
#include "randombytes.h"
#include "ed25519.h"
#include "sha512.h"
#include "ge.h"

int ed25519_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                              const unsigned char *seed)
{
    ge_p3 A;

    crypto_hash_sha512(sk,seed,32);
    sk[0] &= 248;
    sk[31] &= 63;
    sk[31] |= 64;

    ge_scalarmult_base(&A,sk);
    ge_p3_tobytes(pk,&A);

    memmove(sk, seed, 32);
    memmove(sk + 32, pk, 32);
    return 0;
}

int ed25519_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    unsigned char seed[32];
    int           ret;

    ed25519_randombytes(seed, sizeof seed);
    ret = ed25519_sign_seed_keypair(pk, sk, seed);
    memset(seed, 0, sizeof seed);

    return ret;
}
