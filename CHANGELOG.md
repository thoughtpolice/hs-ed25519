0.0.3.0
-------

  * Tighten dependencies everywhere for cleaner builds.
  * Fix old code (including compatibility with newer `QuickCheck` versions)
  * New API: `toPublicKey :: SecretKey -> PublicKey`
    - Used to derive the public key for a given secret key
  * New API: `createKeypairFromSeed :: ByteString -> (PublicKey, SecretKey)`
    - Used to create a deterministic Ed25519 keypair from a 32-byte seed.
  * For GHC 7.2 and above, both `PublicKey` and `SecretKey` are
    now instances of `Generic`.
  * Improved documentation.
  * Various cleanups and some fixes in the tests and benchmarks.

0.0.2.0
-------

  * Portability improvements.

0.0.1.0
-------

  * Initial release.
