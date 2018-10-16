//
// ed25519 has seen one or two format changes before (particularly in the
// initial version released in 'nacl' vs the version used in libsodium), so
// this test just roundtrips some signatures between haskell/libsodium and
// ensures that the signatures are equivalent to each other (as ed25519 is
// deterministic, and libsodium may choose a different, faster implementation
// than our own ref10 copy)

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sodium.h>

// embedded binary files
#include "bins.h"

int
main(void)
{
  int r = 0;

  if (sodium_init() < 0) return EXIT_FAILURE;

  assert(blob_sig_len == crypto_sign_BYTES);
  assert(foo_pk_len == crypto_sign_PUBLICKEYBYTES);

  // verify the haskell-created signature is considered valid
  r = crypto_sign_verify_detached(blob_sig, blob, blob_len, foo_pk);
  assert (r == 0 && "detached verify did not succeed");

  // verify that a signature created by libsodium is equivalent
  // (because ed25519 is deterministic)
  char sig[crypto_sign_BYTES];
  crypto_sign_detached(sig, NULL, blob, blob_len, foo_sk);

  r = memcmp(sig, blob_sig, crypto_sign_BYTES);
  assert(r == 0 && "libsodium signature isn't equivalent to the haskell one!");

#if 0
  // for debugging, in case you want to see the signatures libsodium creates to
  // compare them

  int fd = open("test.sig", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
  assert (fd > 0);
  r = write(fd, sig, crypto_sign_BYTES);
  assert (r == crypto_sign_BYTES);
  close(fd);
#endif

  printf("ok\n");
  return EXIT_SUCCESS;
}
