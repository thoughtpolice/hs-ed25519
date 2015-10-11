0.0.5.0
-------

  * Added doctests and crash course introduction.
  * Fixed some bugs in the test harnesses.
  * Fixed some `hlint` gripes.
  * Minor touchups elsewhere.

0.0.4.0
-------

  * `Crypto.Sign.Ed25519` is now marked `-XTrustworthy`.
  * There is now a `Generic` instance for `Signature` on GHC 7.2 and above.
  * **DEPRECATED**: `createKeypairFromSeed` due to unsafety.
    - Use `createKeypairFromSeed_` instead, which will return a `Maybe`.
  * **DEPRECATED**: `sign'` and `verify'` for bad naming
    - Use `dsign` and `dverify` instead.
  * Improve benchmarks.
  * Huge overhaul to documentation, including design and implementation notes.

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
