#ifndef SHA512_H
#define SHA512_H

#define crypto_hash_BYTES      64
#define crypto_hash_STATEBYTES 64
#define crypto_hash_BLOCKBYTES 128

static inline int crypto_hash_sha512(unsigned char *out,
                                     const unsigned char *in,
                                     unsigned long long inlen);

#endif /* SHA512_H */
