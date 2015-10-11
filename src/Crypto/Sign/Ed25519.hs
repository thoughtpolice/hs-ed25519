{-# LANGUAGE CPP #-}
{-# LANGUAGE ForeignFunctionInterface #-}

#if __GLASGOW_HASKELL__ >= 702
{-# LANGUAGE Trustworthy #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
#endif

-- |
-- Module      : Crypto.Sign.Ed25519
-- Copyright   : (c) Austin Seipp 2013-2015
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- This module provides bindings to the Ed25519 public-key signature
-- system, including detached signatures. The documentation should be
-- self explanatory with complete examples.
--
-- Below the basic documentation you'll find API, performance and
-- security notes, which you may want to read carefully before
-- continuing. (Nonetheless, @Ed25519@ is one of the easiest-to-use
-- signature systems around, and is simple to get started with for
-- building more complex protocols. But the below details are highly
-- educational and should help adjust your expectations properly.)
--
-- For more reading on the underlying implementation and theory
-- (including how to get a copy of the Ed25519 software),
-- visit <http://ed25519.cr.yp.to>. There are two papers that discuss
-- the design of EdDSA/Ed25519 in detail:
--
--   * <http://ed25519.cr.yp.to/ed25519-20110926.pdf "High-speed high-security signatures"> -
--   The original specification by Bernstein, Duif, Lange, Schwabe,
--   and Yang.
--
--   * <http://ed25519.cr.yp.to/eddsa-20150704.pdf "EdDSA for more curves"> -
--   An extension of the original EdDSA specification allowing it to
--   be used with more curves (such as Ed41417, or Ed488), as well as
--   defining the support for __message prehashing__. The original
--   EdDSA is easily derived from the extended version through a few
--   parameter defaults. (This package won't consider non-Ed25519
--   EdDSA systems any further.)
--
module Crypto.Sign.Ed25519
       ( -- * A crash course introduction
         -- $intro

         -- * Keypair creation
         -- $creatingkeys
         PublicKey(..)          -- :: *
       , SecretKey(..)          -- :: *
       , createKeypair          -- :: IO (PublicKey, SecretKey)
       , createKeypairFromSeed_ -- :: ByteString -> Maybe (PublicKey, SecretKey)
       , createKeypairFromSeed  -- :: ByteString -> (PublicKey, SecretKey)
       , toPublicKey            -- :: SecretKey -> PublicKey

         -- * Signing and verifying messages
         -- $signatures
       , sign                 -- :: SecretKey -> ByteString -> ByteString
       , verify               -- :: PublicKey -> ByteString -> Bool

         -- * Detached signatures
         -- $detachedsigs
       , Signature(..)        -- :: *
       , dsign                -- :: SecretKey -> ByteString -> Signature
       , dverify              -- :: PublicKey -> ByteString -> Signature -> Bool
         -- ** Deprecated interface
         -- | The below interface is deprecated but functionally
         -- equivalent to the above; it simply has \"worse\" naming and will
         -- eventually be removed.
       , sign'                -- :: SecretKey -> ByteString -> Signature
       , verify'              -- :: PublicKey -> ByteString -> Signature -> Bool

         -- * Security, design and implementation notes
         -- $security

         -- ** EdDSA background and properties
         -- $background

         -- *** Generation of psuedo-random seeds
         -- $seedgen

         -- ** Performance and implementation
         -- $performance

         -- ** Secure @'SecretKey'@ storage
         -- $keystorage

         -- ** Prehashing and large input messages
         -- $prehashing
       ) where
import           Foreign.C.Types
import           Foreign.ForeignPtr       (withForeignPtr)
import           Foreign.Marshal.Alloc    (alloca)
import           Foreign.Ptr
import           Foreign.Storable

import           System.IO.Unsafe         (unsafePerformIO)

import           Data.Maybe               (fromMaybe)

import           Data.ByteString          as S
import           Data.ByteString.Internal as SI
import           Data.ByteString.Unsafe   as SU
import           Data.Word

#if __GLASGOW_HASKELL__ >= 702
import           GHC.Generics             (Generic)
#endif

-- Doctest setup with some examples

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> import Data.ByteString.Char8
-- >>> let hash        x = x
-- >>> let readBigFile x = return x

--------------------------------------------------------------------------------
-- Key creation

-- $creatingkeys
--
-- Ed25519 signatures start off life by having a keypair created,
-- using @'createKeypair'@ or @'createKeypairFromSeed_'@, which gives
-- you back a @'SecretKey'@ you can use for signing messages, and a
-- @'PublicKey'@ your users can use to verify you in fact authored the
-- messages.
--
-- Ed25519 is a /deterministic signature system/, meaning that you may
-- always recompute a @'PublicKey'@ and a @'SecretKey'@ from an
-- initial, 32-byte input seed. Despite that, the default interface
-- almost all clients will wish to use is simply @'createKeypair'@,
-- which uses an Operating System provided source of secure randomness
-- to seed key creation. (For more information, see the security notes
-- at the bottom of this page.)

-- | A @'PublicKey'@ created by @'createKeypair'@.
--
-- @since 0.0.1.0
newtype PublicKey = PublicKey { unPublicKey :: ByteString
                                -- ^ Unwrapper for getting the raw
                                -- @'ByteString'@ in a
                                -- @'PublicKey'@. In general you
                                -- should not make any assumptions
                                -- about the underlying blob; this is
                                -- only provided for interoperability.
                              }
        deriving (Eq, Show, Ord)

-- | A @'SecretKey'@ created by @'createKeypair'@. __Be sure to keep this__
-- __safe!__
--
-- @since 0.0.1.0
newtype SecretKey = SecretKey { unSecretKey :: ByteString
                                -- ^ Unwrapper for getting the raw
                                -- @'ByteString'@ in a
                                -- @'SecretKey'@. In general you
                                -- should not make any assumptions
                                -- about the underlying blob; this is
                                -- only provided for interoperability.
                              }
        deriving (Eq, Show, Ord)

#if __GLASGOW_HASKELL__ >= 702
deriving instance Generic PublicKey
deriving instance Generic SecretKey
#endif

-- | Randomly generate a @'SecretKey'@ and @'PublicKey'@ for doing
-- authenticated signing and verification. This essentically calls
-- @'createKeypairFromSeed_'@ with a randomly generated 32-byte seed,
-- the source of which is operating-system dependent (see security
-- notes below). However, internally it is implemented more
-- efficiently (with less allocations and copies).
--
-- If you wish to use your own seed (for design purposes so you may
-- recreate keys, due to high paranoia, or because you have your own
-- source of randomness), please use @'createKeypairFromSeed_'@
-- instead.
--
-- @since 0.0.1.0
createKeypair :: IO (PublicKey, SecretKey)
createKeypair = do
  pk <- SI.mallocByteString cryptoSignPUBLICKEYBYTES
  sk <- SI.mallocByteString cryptoSignSECRETKEYBYTES

  _ <- withForeignPtr pk $ \ppk -> do
    _ <- withForeignPtr sk $ \psk -> do
      _ <- c_crypto_sign_keypair ppk psk
      return ()
    return ()

  return (PublicKey $ SI.fromForeignPtr pk 0 cryptoSignPUBLICKEYBYTES,
          SecretKey $ SI.fromForeignPtr sk 0 cryptoSignSECRETKEYBYTES)

-- | Generate a deterministic @'PublicKey'@ and @'SecretKey'@ from a
-- given 32-byte seed, allowing you to recreate a keypair at any point
-- in time, providing you have the seed available.
--
-- If the input seed is not 32 bytes in length,
-- @'createKeypairFromSeed_'@ returns @'Nothing'@. Otherwise, it
-- always returns @'Just' (pk, sk)@ for the given seed.
--
-- __/NOTE/__: This function will replace @'createKeypairFromSeed'@ in
-- the future.
--
-- @since 0.0.4.0
createKeypairFromSeed_ :: ByteString                  -- ^ 32-byte seed
                      -> Maybe (PublicKey, SecretKey) -- ^ Resulting keypair
createKeypairFromSeed_ seed
  | S.length seed /= cryptoSignSEEDBYTES = Nothing
  | otherwise = unsafePerformIO $ do
    pk <- SI.mallocByteString cryptoSignPUBLICKEYBYTES
    sk <- SI.mallocByteString cryptoSignSECRETKEYBYTES

    _ <- SU.unsafeUseAsCString seed $ \pseed -> do
      _ <- withForeignPtr pk $ \ppk -> do
        _ <- withForeignPtr sk $ \psk -> do
          _ <- c_crypto_sign_seed_keypair ppk psk pseed
          return ()
        return ()
      return ()

    return $ Just (PublicKey $ SI.fromForeignPtr pk 0 cryptoSignPUBLICKEYBYTES,
                   SecretKey $ SI.fromForeignPtr sk 0 cryptoSignSECRETKEYBYTES)

-- | Generate a deterministic @'PublicKey'@ and @'SecretKey'@ from a
-- given 32-byte seed, allowing you to recreate a keypair at any point
-- in time, providing you have the seed available.
--
-- Note that this will @'error'@ if the given input is not 32 bytes in
-- length, so you must be careful with this input.
--
-- @since 0.0.3.0
createKeypairFromSeed :: ByteString             -- ^ 32-byte seed
                      -> (PublicKey, SecretKey) -- ^ Resulting keypair
createKeypairFromSeed seed
  = fromMaybe (error "seed has incorrect length") (createKeypairFromSeed_ seed)
{-# DEPRECATED createKeypairFromSeed "This function is unsafe as it can @'fail'@ with an invalid input. Use @'createKeypairWithSeed_'@ instead." #-}

-- | Derive the @'PublicKey'@ for a given @'SecretKey'@. This is a
-- convenience which allows (for example) using @'createKeypair'@ and
-- only ever storing the returned @'SecretKey'@ for any future
-- operations.
--
-- @since 0.0.3.0
toPublicKey :: SecretKey -- ^ Any valid @'SecretKey'@
            -> PublicKey -- ^ Corresponding @'PublicKey'@
toPublicKey = PublicKey . S.drop prefixBytes  . unSecretKey
  where prefixBytes = cryptoSignSECRETKEYBYTES - cryptoSignPUBLICKEYBYTES

--------------------------------------------------------------------------------
-- Default, non-detached API

-- $signatures
--
-- By default, the Ed25519 interface computes a /signed message/ given
-- a @'SecretKey'@ and an input message. A /signed message/ consists
-- of an Ed25519 signature (of unspecified format), followed by the
-- input message.  This means that given an input message of @M@
-- bytes, you get back a message of @M+N@ bytes where @N@ is a
-- constant (the size of the Ed25519 signature blob).
--
-- The default interface in this package reflects that. As a result,
-- any time you use @'sign'@ or @'verify'@ you will be given back the
-- full input, and then some.
--

-- | Sign a message with a particular @'SecretKey'@. Note that the resulting
-- signed message contains both the message itself, and the signature
-- attached. If you only want the signature of a given input string,
-- please see @'dsign'@.
--
-- @since 0.0.1.0
sign :: SecretKey
     -- ^ Signers @'SecretKey'@
     -> ByteString
     -- ^ Input message
     -> ByteString
     -- ^ Resulting signed message
sign (SecretKey sk) xs =
  unsafePerformIO . SU.unsafeUseAsCStringLen xs $ \(mstr,mlen) ->
    SU.unsafeUseAsCString sk $ \psk ->
      SI.createAndTrim (mlen+cryptoSignBYTES) $ \out ->
        alloca $ \smlen -> do
          _ <- c_crypto_sign out smlen mstr (fromIntegral mlen) psk
          fromIntegral `fmap` peek smlen
{-# INLINE sign #-}

-- | Verifies a signed message against a @'PublicKey'@. Note that the input
-- message must be generated by @'sign'@ (that is, it is the message
-- itself plus its signature). If you want to verify an arbitrary
-- signature against an arbitrary message, please see @'dverify'@.
--
-- @since 0.0.1.0
verify :: PublicKey
       -- ^ Signers @'PublicKey'@
       -> ByteString
       -- ^ Signed message
       -> Bool
       -- ^ Verification result
verify (PublicKey pk) xs =
  unsafePerformIO . SU.unsafeUseAsCStringLen xs $ \(smstr,smlen) ->
    SU.unsafeUseAsCString pk $ \ppk ->
      alloca $ \pmlen -> do
        out <- SI.mallocByteString smlen
        r <- withForeignPtr out $ \pout ->
               c_crypto_sign_open pout pmlen smstr (fromIntegral smlen) ppk

        return (r == 0)
{-# INLINE verify #-}

--------------------------------------------------------------------------------
-- Detached signature support

-- $detachedsigs
--
-- This package also provides an alternative interface for /detached/
-- /signatures/, which is more in-line with what you might
-- traditionally expect from a signing API. In this mode, the
-- @'dsign'@ and @'dverify'@ interfaces simply return a constant-sized
-- blob, representing the Ed25519 signature of the input message.
--
-- This allows users to independently download, verify or attach
-- signatures to messages in any way they see fit - for example, by
-- providing a tarball file to download, with a corresponding @.sig@
-- file containing the Ed25519 signature from the author.

-- | A @'Signature'@ which is detached from the message it signed.
--
-- @since 0.0.1.0
newtype Signature = Signature { unSignature :: ByteString
                                -- ^ Unwrapper for getting the raw
                                -- @'ByteString'@ in a
                                -- @'Signature'@. In general you
                                -- should not make any assumptions
                                -- about the underlying blob; this is
                                -- only provided for interoperability.
                              }
        deriving (Eq, Show, Ord)

#if __GLASGOW_HASKELL__ >= 702
deriving instance Generic Signature
#endif

-- | Sign a message with a particular @'SecretKey'@, only returning the
-- @'Signature'@ without the message.
--
-- @since 0.0.4.0
dsign :: SecretKey
      -- ^ Signers @'SecretKey'@
      -> ByteString
      -- ^ Input message
      -> Signature
      -- ^ Message @'Signature'@, without the message
dsign sk xs =
  let sm = sign sk xs
      l  = S.length sm
  in Signature $! S.take (l - S.length xs) sm
{-# INLINE dsign #-}

-- | Verify a message with a detached @'Signature'@ against a given
-- @'PublicKey'@.
--
-- @since 0.0.4.0
dverify :: PublicKey
        -- ^ Signers @'PublicKey'@
        -> ByteString
        -- ^ Raw input message
        -> Signature
        -- ^ Message @'Signature'@
        -> Bool
        -- ^ Verification result
dverify pk xs (Signature sig) = verify pk (sig `S.append` xs)
{-# INLINE dverify #-}

-- | Sign a message with a particular @'SecretKey'@, only returning the
-- @'Signature'@ without the message. Simply an alias for @'dsign'@.
--
-- @since 0.0.1.0
sign' :: SecretKey
      -- ^ Signers @'SecretKey'@
      -> ByteString
      -- ^ Input message
      -> Signature
      -- ^ Message @'Signature'@, without the message
sign' sk xs = dsign sk xs
{-# DEPRECATED sign' "@'sign''@ will be removed in a future release; use @'dsign'@ instead." #-}

-- | Verify a message with a detached @'Signature'@ against a given
-- @'PublicKey'@. Simply an alias for @'dverify'@.
--
-- @since 0.0.1.0
verify' :: PublicKey
        -- ^ Signers @'PublicKey'@
        -> ByteString
        -- ^ Raw input message
        -> Signature
        -- ^ Message @'Signature'@
        -> Bool
        -- ^ Verification result
verify' pk xs sig = dverify pk xs sig
{-# DEPRECATED verify' "@'verify''@ will be removed in a future release; use @'dverify'@ instead." #-}

--------------------------------------------------------------------------------
-- FFI binding

cryptoSignSECRETKEYBYTES :: Int
cryptoSignSECRETKEYBYTES = 64

cryptoSignPUBLICKEYBYTES :: Int
cryptoSignPUBLICKEYBYTES = 32

cryptoSignBYTES :: Int
cryptoSignBYTES = 64

cryptoSignSEEDBYTES :: Int
cryptoSignSEEDBYTES = 32

foreign import ccall unsafe "ed25519_sign_seed_keypair"
  c_crypto_sign_seed_keypair :: Ptr Word8 -> Ptr Word8
                             -> Ptr CChar -> IO CInt

foreign import ccall unsafe "ed25519_sign_keypair"
  c_crypto_sign_keypair :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "ed25519_sign"
  c_crypto_sign :: Ptr Word8 -> Ptr CULLong ->
                   Ptr CChar -> CULLong -> Ptr CChar -> IO CULLong

foreign import ccall unsafe "ed25519_sign_open"
  c_crypto_sign_open :: Ptr Word8 -> Ptr CULLong ->
                        Ptr CChar -> CULLong -> Ptr CChar -> IO CInt

--------------------------------------------------------------------------------
-- Documentation and notes

-- $intro
--
-- The simplest use of this library is one where you probably need to
-- sign short messages, so they can be verified independently. That's
-- easily done by first creating a keypair with @'createKeypair'@, and
-- using @'sign'@ to create a signed message. Then, you can distribute
-- your public key and the signed message, and any recipient can
-- verify that message:
--
-- >>> (pk, sk) <- createKeypair
-- >>> let msg = sign sk "Hello world"
-- >>> verify pk msg
-- True
--
-- This interface is fine if your messages are small and simple binary
-- blobs you want to verify in an opaque manner, but internally it
-- creates a copy of the input message. Often, you'll want the
-- signature independently of the message, and that can be done with
-- @'dsign'@ and @'dverify'@. Naturally, verification fails if the
-- message is incorrect:
--
-- >>> (pk, sk) <- createKeypair
-- >>> let msg = "Hello world" :: ByteString
-- >>> let sig = dsign sk msg
-- >>> dverify pk msg sig
-- True
-- >>> dverify pk "Hello world" sig
-- True
-- >>> dverify pk "Goodbye world" sig
-- False
--
-- Finally, it's worth keeping in mind this package doesn't expose any
-- kind of incremental interface, and signing/verification can be
-- expensive. So, if you're dealing with __large inputs__, you can
-- hash the input with a robust, fast cryptographic hash, and then
-- sign that (for example, the @hash@ function below could be
-- __SHA-512__ or __BLAKE2b__):
--
-- >>> (pk, sk) <- createKeypair
-- >>> msg <- readBigFile "blob.tar.gz" :: IO ByteString
-- >>> let sig = dsign sk (hash msg)
-- >>> dverify pk (hash msg) sig
-- True
--
-- See the notes at the bottom of this module for more on message
-- prehashing (as it acts slightly differently in an EdDSA system).

-- $security
--
-- Included below are some notes on the security aspects of the
-- Ed25519 signature system, its implementation and design, this
-- package, and suggestions for how you might use it properly.



-- $background
--
-- Ed25519 is a specific instantiation of the __EdDSA__ digital
-- signature scheme - a high performance, secure-by-design variant of
-- Schnorr signatures based on "Twisted Edwards Curves" (hence the
-- name __Ed__DSA). The (__extended__) EdDSA system is defined by an
-- elliptic curve:
--
-- > ax^2 + y^2 = 1 + d*x^2*y^2
--
-- along with several other parameters, chosen by the implementation
-- in question. These parameters include @a@, @d@, and a field @GF(p)@
-- where @p@ is prime. Ed25519 specifically uses @d = -121665/121666@,
-- @a = -1@, and the finite field @GF((2^155)-19)@, where @(2^155)-19@
-- is a prime number (which is also the namesake of the algorithm in
-- question, as Ed__25519__). This yields the equation:
--
-- > -x^2 + y^2 = 1 - (121665/121666)*x^2*y^2
--
-- This curve is \'birationally equivalent\' to the well-known
-- Montgomery curve \'Curve25519\', which means that EdDSA shares the
-- same the difficult problem as Curve25519: that of the Elliptic
-- Curve Discrete Logarithm Problem (ECDLP). Ed25519 is currently
-- still the recommended EdDSA curve for most deployments.
--
-- As Ed25519 is an elliptic curve algorithm, the security level
-- (i.e. number of computations taken to find a solution to the ECDLP
-- with the fastest known attacks) is roughly half the key size in
-- bits, as it stands. As Ed25519 features 32-byte keys, the security
-- level of Ed25519 is thus @2^((32*8)/2) = 2^128@, far beyond any
-- attacker capability (modulo major breakthroughs for the ECDLP,
-- which would likely catastrophically be applicable to other systems
-- too).
--
-- Ed25519 designed to meet the standard notion of unforgeability for
-- a public-key signature scheme under chosen-message attacks. This
-- means that even should the attacker be able to request someone sign
-- any arbitrary message of their choice (hence /chosen-message/),
-- they are still not capable of any forgery what-so-ever, even the
-- weakest kind of \'existential forgery\'.


-- $seedgen
--
-- Seed generation as done by @'createKeypair'@ uses Operating System
-- provided APIs for generating cryptographically secure psuedo-random
-- data to be used as an Ed25519 key seed. Your own deterministic keys
-- may be generated using @'createKeypairFromSeed_'@, provided you have
-- your own cryptographically secure psuedo-random data from
-- somewhere.
--
-- On __Linux__, __OS X__ and __other Unix__ machines, the
-- @\/dev\/urandom@ device is consulted internally in order to generate
-- random data. In the current implementation, a global file
-- descriptor is used through the lifetime of the program to
-- periodically get psuedo-random data.
--
-- On __Windows__, the @CryptGenRandom@ API is used internally. This
-- does not require file handles of any kind, and should work on all
-- versions of Windows. (Windows may instead use @RtlGenRandom@ in the
-- future for even less overhead.)
--
-- In the future, there are plans for this package to internally take
-- advantage of better APIs when they are available; for example, on
-- Linux 3.17 and above, @getrandom(2)@ provides psuedo-random data
-- directly through the internal pool provided by @\/dev\/urandom@,
-- without a file descriptor. Similarly, OpenBSD provides the
-- @arc4random(3)@ family of functions, which internally uses a data
-- generator based on ChaCha20. These should offer somewhat better
-- efficiency, and also avoid file-descriptor exhaustion attacks which
-- could lead to denial of service in some scenarios.



-- $performance
--
-- Ed25519 is exceptionally fast, although the implementation provided
-- by this package is not the fastest possible implementation. Indeed,
-- it is rather slow, even by non-handwritten-assembly standards of
-- speed. That said, it should still be competitive with most other
-- signature schemes: the underlying implementation is @ref10@ from
-- <http://bench.cr.yp.to/ SUPERCOP>, authored by Daniel J. Bernstein,
-- which is within the
-- <http://bench.cr.yp.to/impl-sign/ed25519.html realm of competition>
-- against some assembly implementations (only 2x slower), and much
-- faster than the slow reference implementation (25x slower). When up
-- <http://bench.cr.yp.to/web-impl/amd64-skylake-crypto_sign.html against RSA>
-- signatures (ronald3072) on a modern Intel machine, it is still __15x__
-- faster at signing messages /at the same 128-bit security level/.
--
-- On the author's Sandy Bridge i5-2520M 2.50GHz CPU, the benchmarking
-- code included with the library reports the following numbers for
-- the Haskell interface:
--
-- @
-- benchmarking deterministic key generation
-- time                 250.0 μs   (249.8 μs .. 250.3 μs)
--                      1.000 R²   (1.000 R² .. 1.000 R²)
-- mean                 250.0 μs   (249.9 μs .. 250.2 μs)
-- std dev              467.0 ns   (331.7 ns .. 627.9 ns)
--
-- benchmarking signing a 256 byte message
-- time                 273.2 μs   (273.0 μs .. 273.4 μs)
--                      1.000 R²   (1.000 R² .. 1.000 R²)
-- mean                 273.3 μs   (273.1 μs .. 273.5 μs)
-- std dev              616.2 ns   (374.1 ns .. 998.8 ns)
--
-- benchmarking verifying a signature
-- time                 635.7 μs   (634.6 μs .. 637.3 μs)
--                      1.000 R²   (1.000 R² .. 1.000 R²)
-- mean                 635.4 μs   (635.0 μs .. 636.0 μs)
-- std dev              1.687 μs   (999.3 ns .. 2.487 μs)
--
-- benchmarking roundtrip 256-byte sign/verify
-- time                 923.6 μs   (910.0 μs .. 950.6 μs)
--                      0.998 R²   (0.996 R² .. 1.000 R²)
-- mean                 913.2 μs   (910.6 μs .. 923.0 μs)
-- std dev              15.93 μs   (1.820 μs .. 33.72 μs)
-- @
--
-- In the future, this package will hopefully provide an opt-in (or
-- possibly default) implementation of
-- <https://github.com/floodyberry/ed25519-donna ed25519-donna>, which
-- should dramatically increase speed at no cost for many/all
-- platforms.



-- $keystorage
--
-- By default, keys are not encrypted in any meaningful manner with
-- any mechanism, and this package does not provide any means of doing
-- so. As a result, your secret keys are only as secure as the
-- computing environment housing them - a server alone out on the
-- hostile internet, or a USB stick that's susceptable to theft.
--
-- If you wish to add some security to your keys, a very simple and
-- effective way is __to add a password to your @'SecretKey'@ with a__
-- __KDF and a hash__. How does this work?
--
--   * First, hash the secret key you have generated. Use this as a
--   __checksum__ of the original key. Truncating this hash to save
--   space is acceptable; see below for more details and boring
--   hemming and hawing.
--
--   * Given an input password, use a KDF to stretch it to the length
--   of a @'SecretKey'@.
--
--   * XOR the @'SecretKey'@ bytewise, directly with the output of
--   your chosen KDF.
--
--   * Attach the checksum you generated to the resulting encrypted
--   key, and store it as you like.
--
-- In this mode, your key is XOR'd with the psuedo-random result of a
-- KDF, which will stretch simple passwords like "I am the robot" into
-- a suitable amount of psuedo-random data for a given secret key to
-- be encrypted with. Decryption is simply the act of taking the
-- password, generating the psuedo-random stream again, XORing the key
-- bytewise, and validating the checksum. In this sense, you are
-- simply using a KDF as a short stream cipher.
--
-- __Recommendation__: Encrypt keys by stretching a password with
-- __scrypt__ (or __yescrypt__), using better-than-default parameters.
-- (These being @N = 2^14@, @r = 8@, @p = 1@; the default results in
-- 16mb of memory per invocation, and this is the recommended default
-- for 'interactive systems'; signing keys may be loaded on-startup
-- for some things however, so it may be profitable to increase
-- security as well as memory use in these cases. For example, at @N =
-- 2^18@, @r = 10@ and @p = 2@, you'll get 320mb of memory per use,
-- which may be acceptable for dramatic security increases. See
-- elsewhere for exact memory use.) Checksums may be computed with an
-- exceptionally fast hash such as __BLAKE2b__.
--
-- __Bonus points__: Print that resulting checksum + key out on a
-- piece of paper (~100 bytes, tops), and put /that/ somewhere safe.
--
-- __Q__: What is the hash needed for? __A__: A simple file integrity
-- check. Rather than invoke complicated methods of verifying if an
-- ed25519 keypair is valid (as it is simply an opaque binary blob,
-- for all intents and purposes), especially after 'streaming
-- decryption', it's far easier to simply compute and compare against
-- a checksum of the original to determine if decryption with your
-- password worked.
--
-- __Q__: Wait, why is it OK to truncate the hash here? That sounds
-- scary. Won't that open up collisions or something like that if they
-- stole my encrypted key?  __A__: No. The hash in this case is only
-- used as a checksum to see if the password is legitimate after
-- running the KDF and XORing with the result. Think about how the
-- \'challenge\' itself is chosen: if you know @H(m)@, do you want to
-- find @m@ itself, or simply find @m'@ where @H(m') = H(m)@?  To
-- forge a signature, you want the original key, @m@. Suppose given an
-- input of 256-bits, we hashed it and truncated to one bit. Finding
-- collisions would be easy: you would only need to try a few times to
-- find a collision or preimage. But you probably found @m'@ such that
-- @H(m') = H(m)@ - you didn't necessarily find @m@ itself. In this
-- sense, finding collisions or preimages of the hash is not useful to
-- the attacker, because you must find the unique @m@.
--
-- __Q__: Okay, why use hashes at all? Why not CRC32? __A__: You could
-- do that, it wouldn't change much. You can really use any kind of
-- error detecting code you want. The thing is, some hashes such as
-- __BLAKE2__ are very fast in things like software (not every CPU has
-- CRC instructions, not all software uses CRC instructions), and
-- you're likely to already have a fast, modern hash function sitting
-- around anyway if you're signing stuff with Ed25519. Why not use it?



-- $prehashing
--
-- __Message prehashing__ (although not an official term in any right)
-- is the idea of first taking an input @x@, using a
-- __cryptographically secure__ hash function @H@ to calculate @y =
-- H(x)@, and then generating a signature via @Sign(secretKey,
-- y)@. The idea is that signing is often expensive, while hashing is
-- often extremely fast. As a result, signing the hash of a message
-- (which should be indistinguishable from a truly random function) is
-- often faster than simply signing the full message alone, and in
-- larger cases can save a significant amount of CPU cycles. However,
-- internally Ed25519 uses a hash function @H@ already to hash the
-- input message for computing the signature. Thus, there is a
-- question - is it appropriate or desireable to hash the input
-- already if this is the case?
--
-- Generally speaking, it's OK to prehash messages before giving them
-- to Ed25519. However, there is a caveat. In the paper
-- <http://ed25519.cr.yp.to/eddsa-20150704.pdf "EdDSA for more curves">,
-- the authors of the original EdDSA enhance the specification by
-- extending it with a message prehash function, @H'@, along with an
-- internal hash @H@. Here, the prehash @H'@ is simply applied to the
-- original message first before anything else. The original EdDSA
-- specification (and the implementation in /this package/) was a
-- trivial case of this enhancement: it was implicit that @H'@ is
-- simply the identity function. We call the case where @H'@ is the
-- identity function __PureEdDSA__, while the case where @H'@ is a
-- cryptographic hash function is known as __HashEdDSA__. (Thus, the
-- interfaces @'sign'@ and @'dsign'@ implement PureEdDSA - while they can
-- be converted to HashEdDSA by simply hashing the @'ByteString'@
-- first with some other function.)
--
-- However, the authors note that HashEdDSA suffers from a weakness
-- that PureEdDSA does not - PureEdDSA is resiliant to collision
-- attacks in the underlying hash function @H@, while HashEdDSA is
-- vulnerable to collisions in @H'@. This is an important
-- distinction. Assume that the attacker finds a collision such that
-- @H'(x) = H'(y)@, and then gets convinces a signer to HashEdDSA-sign
-- @x@ - the attacker may then forge this signature and use it as the
-- same signature as for the message @y@. For a hash function of
-- @N@-bits of output, a collision attack takes roughly @2^(N/2)@
-- operations.
--
-- Ed25519 internally sets @H = SHA-512@ anyway, which has no known
-- collision attacks or weaknesses in any meaningful sense. It is
-- however slower compared to other, more modern hash functions, and
-- is used on the input message in its entirety (and there are no
-- plans to switch the internal implementation of this package, or the
-- standard Ed25519 away from @H = SHA-512@).
--
-- But note: /all other hash-then-sign constructions suffer from/
-- /this/, in the sense they are all vulnerable to collision attacks
-- in @H'@, should you prehash the message. In fact, PureEdDSA is
-- unique (as far as I am aware) in that it is immune to collision
-- attacks in @H@ - should a collision be found, it would not suffer
-- from these forgeries. By this view, it's arguable that /depending/
-- on the HashEdDSA construction (for efficiency or size purposes)
-- when using EdDSA is somewhat less robust, even if SHA-512 or
-- whatever is not very fast. Despite that, just about any /modern/
-- /hash/ you pick is going to be collision resistant to a fine degree
-- (say, 256 bits of output, therefore collisions 'at best' happen in
-- @2^128@ operations), so in practice this robustness issue may not
-- be that big of a deal.
--
-- However, the more pertinent issue is that due to the current design
-- of the API which requires the entire blob to sign up front, using
-- the HashEdDSA construction is often much more convenient, faster
-- and sometimes /necessary/ too. For example, when signing very large
-- messages (such as creating a very large @tar.gz@ file which you
-- wish to sign after creation), it is often convenient and possible
-- to use \'incremental\' hashing APIs to incrementally consume data
-- blocks from the input in a constant amount of memory. At the end of
-- consumption, you can \'finalize\' the data blocks and get back a
-- final N-bit hash, and sign this hash all in a constant amount of
-- memory. With the current API, using PureDSA would require you
-- loading the entire file up front to either sign, or verify it. This
-- is especially unoptimal for possibly smaller, low-memory systems
-- (where decompression, hashing or verification are all best done in
-- constant space if possible).
--
-- Beware however, that if you do this sort of incremental hashing for
-- large blobs, you are __taking untrusted data__ and hashing it
-- __before checking the signature__ - be __exceptionally careful__
-- with data from a possibly untrustworthy source until you can verify
-- the signature.
--
-- So, __some basic guidelines are__:
--
--   - If you are simply not worried about efficiency very much, just
--   use __PureEdDSA__ (i.e.  just use @'sign'@ and @'verify'@
--   directly).
--
--   - If you have __lots of small messages__, use __PureEdDSA__ (i.e.
--   just use @'sign'@ and @'verify'@ directly).
--
--   - If you have to sign/verify __large messages__, possibly __in__
--   __an incremental fashion__, use __HashEdDSA__ with __a fast__
--   __hash__ (i.e.  just hash a message before using @'sign'@ or
--   @'verify'@ on it).
--
--       - A hash like __BLAKE2b__ is recommended. Fast and very secure.
--
--       - Remember: __never touch input data in any form until you__
--       __are done hashing it and verifying the signature__.
--
-- As a result, you should be safe hashing your input before passing
-- it to @'sign'@ or @'dsign'@ in this library if you desire, and it may
-- save you CPU cycles for large inputs. It should be no different
-- than the typical /hash-then-sign/ construction you see elsewhere,
-- with the same downfalls. Should you do this, an extremely
-- fast-yet-secure hash such as __BLAKE2b__ is recommended, which is
-- even faster than MD5 or SHA-1 (and __do not ever use MD5 or__
-- __SHA-1__, on that note - they suffer from collision attacks).
