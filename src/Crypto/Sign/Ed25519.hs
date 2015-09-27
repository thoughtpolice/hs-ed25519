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
-- This module provides bindings to the ed25519 public-key signature
-- system, including detached signatures. The underlying
-- implementation uses the @ref10@ implementation of ed25519 from
-- SUPERCOP, authored by Daniel J Bernstein, and it should be
-- relatively fast.
--
-- Below you'll find API and security notes amongst the documentation,
-- which you may want to read carefully before
-- continuing. (Nonetheless, @ed25519@ is one of the easiest-to-use
-- signature systems around, and is simple to get started with for
-- building more complex protocols.)
--
-- For more information on the underlying implementation and theory
-- (including how to get a copy of the software ed25519 software),
-- visit <http://ed25519.cr.yp.to>.
--
module Crypto.Sign.Ed25519
       ( -- * Keypair creation
         -- $creatingkeys
         PublicKey(..)         -- :: *
       , SecretKey(..)         -- :: *
       , createKeypair         -- :: IO (PublicKey, SecretKey)
       , createKeypairFromSeed -- :: ByteString -> (PublicKey, SecretKey)
       , toPublicKey           -- :: SecretKey -> PublicKey

         -- * Signing and verifying messages
         -- $signatures
       , sign                 -- :: SecretKey -> ByteString -> ByteString
       , verify               -- :: PublicKey -> ByteString -> Bool

         -- * Detached signatures
         -- $detachedsigs
       , Signature(..)        -- :: *
       , sign'                -- :: SecretKey -> ByteString -> Signature
       , verify'              -- :: PublicKey -> ByteString -> Signature -> Bool

         -- * Security notes
         -- $security
       ) where
import           Foreign.C.Types
import           Foreign.ForeignPtr       (withForeignPtr)
import           Foreign.Marshal.Alloc    (alloca)
import           Foreign.Ptr
import           Foreign.Storable

import           System.IO.Unsafe         (unsafePerformIO)

import           Control.Monad            (unless)

import           Data.ByteString          as S
import           Data.ByteString.Internal as SI
import           Data.ByteString.Unsafe   as SU
import           Data.Word

#if __GLASGOW_HASKELL__ >= 702
import           GHC.Generics             (Generic)
#endif

--------------------------------------------------------------------------------
-- Key creation

-- $creatingkeys
--
-- ed25519 signatures start off life by having a keypair created,
-- using @'createKeypair'@ or @'createKeypairFromSeed'@, which gives
-- you back a @'SecretKey'@ you can use for signing messages, and a
-- @'PublicKey'@ your users can use to verify you in fact authored the
-- messages.
--
-- ed25519 is a /deterministic signature system/, meaning that you may
-- always recompute a @'PublicKey'@ and a @'SecretKey'@ from an
-- initial, 32-byte input seed. Despite that, the default interface
-- almost all clients will wish to use is simply @'createKeypair'@,
-- which uses an Operating System provided source of secure randomness
-- to seed key creation. (For more information, see the security notes
-- at the bottom of this page.)

-- | A @'PublicKey'@ created by @'createKeypair'@.
--
-- @since 0.0.1.0
newtype PublicKey = PublicKey { unPublicKey :: ByteString }
        deriving (Eq, Show, Ord)

-- | A @'SecretKey'@ created by @'createKeypair'@. Be sure to keep this
-- safe!
--
-- @since 0.0.1.0
newtype SecretKey = SecretKey { unSecretKey :: ByteString }
        deriving (Eq, Show, Ord)

#if __GLASGOW_HASKELL__ >= 702
deriving instance Generic PublicKey
deriving instance Generic SecretKey
#endif

-- | Randomly generate a @'SecretKey'@ and @'PublicKey'@ for doing
-- authenticated signing and verification. This essentically calls
-- @'createKeypairFromSeed'@ with a randomly generated 32-byte seed,
-- the source of which is operating-system dependent (see security
-- notes below).
--
-- If you wish to use your own seed (for design purposes so you may
-- recreate keys, due to high paranoia, or having your own source of
-- randomness), please use @'createKeypairFromSeed'@ instead.
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
-- Note that this will @'fail'@ if the given input is not 32 bytes in
-- length, so you must be precise with this input.
--
-- @since 0.0.3.0
createKeypairFromSeed :: ByteString             -- ^ 32-byte seed
                      -> (PublicKey, SecretKey) -- ^ Resulting keypair
createKeypairFromSeed seed = unsafePerformIO $ do
  unless (S.length seed == cryptoSignSEEDBYTES)
    (fail "seed has incorrect length")
  pk <- SI.mallocByteString cryptoSignPUBLICKEYBYTES
  sk <- SI.mallocByteString cryptoSignSECRETKEYBYTES

  _ <- SU.unsafeUseAsCString seed $ \pseed -> do
    _ <- withForeignPtr pk $ \ppk -> do
      _ <- withForeignPtr sk $ \psk -> do
        _ <- c_crypto_sign_seed_keypair ppk psk pseed
        return ()
      return ()
    return ()

  return (PublicKey $ SI.fromForeignPtr pk 0 cryptoSignPUBLICKEYBYTES,
          SecretKey $ SI.fromForeignPtr sk 0 cryptoSignSECRETKEYBYTES)

-- | Derive the @'PublicKey'@ for a given @'SecretKey'@ (allowing you
-- to use @'createKeypair'@ and only ever store the returned
-- @'SecretKey'@, for any future operations).
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
-- By default, the ed25519 interface computes a /signed message/ given
-- a @'SecretKey'@ and an input message. A /signed message/ consists
-- of an ed25519 signature (of unspecified format), followed by the
-- input message.  This means that given an input message of @M@
-- bytes, you get back a message of @M+N@ bytes where @N@ is a
-- constant (the size of the ed25519 signature blob).
--
-- The default interface in this package reflects that. As a result,
-- any time you use @'sign'@ or @'verify'@ you will be given back the
-- full input, and then some.
--

-- | Sign a message with a particular @'SecretKey'@. Note that the resulting
-- signed message contains both the message itself, and the signature
-- attached. If you only want the signature of a given input string,
-- please see @'sign''@.
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
-- signature against an arbitrary message, please see @'verify''@.
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
-- /signatures/, which is more in-line with what you would
-- traditionally expect from a signing API. In this mode, the
-- @'sign''@ and @'verify''@ interfaces simply return a constant-sized
-- blob, representing the ed25519 signature of the input message.
--
-- This allows users to independently download, verify or attach
-- signatures to messages in any way they see fit, for example, by
-- providing a tarball file to download, with a corresponding @.sig@
-- file containing the ed25519 signature from the author.

-- | A @'Signature'@ which is detached from the message it signed.
--
-- @since 0.0.1.0
newtype Signature = Signature { unSignature :: ByteString }
        deriving (Eq, Show, Ord)

-- | Sign a message with a particular @'SecretKey'@, only returning the
-- @'Signature'@ without the message.
--
-- @since 0.0.1.0
sign' :: SecretKey
      -- ^ Signers @'SecretKey'@
      -> ByteString
      -- ^ Input message
      -> Signature
      -- ^ Message @'Signature'@, without the message
sign' sk xs =
  let sm = sign sk xs
      l  = S.length sm
  in Signature $! S.take (l - S.length xs) sm
{-# INLINE sign' #-}

-- | Verify a message with a detached @'Signature'@ against a given
-- @'PublicKey'@.
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
verify' pk xs (Signature sig) = verify pk (sig `S.append` xs)
{-# INLINE verify' #-}

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

-- $security
--
-- Lorem ipsum...
