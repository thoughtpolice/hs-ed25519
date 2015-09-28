#ifndef _ED25519_H_
#define _ED25519_H_

#define crypto_sign_SECRETKEYBYTES 64
#define crypto_sign_PUBLICKEYBYTES 32
#define crypto_sign_BYTES          64
#define crypto_sign_PRIMITIVE "ed25519"
#define crypto_sign_IMPLEMENTATION crypto_sign_ed25519_IMPLEMENTATION
#define crypto_sign_VERSION crypto_sign_ed25519_VERSION

int ed25519_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                              const unsigned char *seed);
int ed25519_sign_keypair(unsigned char *pk,unsigned char *sk);
int ed25519_sign(unsigned char *sm,unsigned long long *smlen,
                 const unsigned char *m,unsigned long long mlen,
                 const unsigned char *sk);
int ed25519_sign_open(unsigned char *m,unsigned long long *mlen,
                      const unsigned char *sm,unsigned long long smlen,
                      const unsigned char *pk);

#endif /* _ED25519_H_ */
