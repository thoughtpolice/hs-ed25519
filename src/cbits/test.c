#include <stdio.h>
#include <assert.h>
#include "ed25519.h"

unsigned char pk[crypto_sign_PUBLICKEYBYTES];
unsigned char sk[crypto_sign_SECRETKEYBYTES];

int main()
{
  int r = 0;

  ed25519_sign_keypair(pk,sk);
  printf("Keypair generated.\n");

  unsigned char *msg = "Hello";
  unsigned char sm[5+crypto_sign_BYTES];
  unsigned long long smlen;

  r = ed25519_sign(sm, &smlen, msg, 5, sk);
  assert(r == 0);
  printf("Signed message (length = %u)\n",smlen);

  unsigned long long mlen;
  unsigned char m[5+crypto_sign_BYTES];

  r = ed25519_sign_open(m, &mlen, sm, smlen, pk);
  assert(r == 0);
  printf("Verified message (length = %u)\n",mlen);

  return 0;
}
