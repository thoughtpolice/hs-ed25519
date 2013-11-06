#ifndef _WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* it's really stupid that there isn't a syscall for this */

static int fd = -1;

void ed25519_randombytes(unsigned char *x,unsigned long long xlen)
{
  int i;

  if (fd == -1) {
    for (;;) {
      fd = open("/dev/urandom",O_RDONLY);
      if (fd != -1) break;
      sleep(1);
    }
  }

  while (xlen > 0) {
    if (xlen < 1048576) i = xlen; else i = 1048576;

    i = read(fd,x,i);
    if (i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
}

#else
#include <windows.h>
#include <wincrypt.h>

void ed25519_randombytes(unsigned char *x,unsigned long long xlen)
{
  HCRYPTPROV prov = 0;

  CryptAcquireContextW(&prov, NULL, NULL,
    PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);

  CryptGenRandom(prov, xlen, x);
  CryptReleaseContext(prov, 0);
}

#endif /* _WIN32  */
