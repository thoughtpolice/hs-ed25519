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
-- SUPERCOP, and should be relatively fast.
--
-- For more information (including how to get a copy of the software)
-- visit <http://ed25519.cr.yp.to>.
--
module Crypto.Sign.Ed25519
       ( -- * Keypair creation
         PublicKey(..)         -- :: *
       , SecretKey(..)         -- :: *
       , createKeypair         -- :: IO (PublicKey, SecretKey)
       , createKeypairFromSeed -- :: ByteString -> (PublicKey, SecretKey)
       , toPublicKey           -- :: SecretKey -> PublicKey

         -- * Signing and verifying messages
       , sign                 -- :: SecretKey -> ByteString -> ByteString
       , verify               -- :: PublicKey -> ByteString -> Bool

         -- * Detached signatures
       , Signature(..)        -- :: *
       , sign'                -- :: SecretKey -> ByteString -> Signature
       , verify'              -- :: PublicKey -> ByteString -> Signature -> Bool
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

-- | A @'SecretKey'@ created by @'createKeypair'@. Be sure to keep this
-- safe!
newtype SecretKey = SecretKey { unSecretKey :: ByteString }
        deriving (Eq, Show, Ord)

-- | A @'PublicKey'@ created by @'createKeypair'@.
newtype PublicKey = PublicKey { unPublicKey :: ByteString }
        deriving (Eq, Show, Ord)

#if __GLASGOW_HASKELL__ >= 702
deriving instance Generic PublicKey
deriving instance Generic SecretKey
#endif

-- | Randomly generate a @'SecretKey'@ and @'PublicKey'@ for doing
-- authenticated signing and verification.
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
-- given 32-byte seed. Note that this will @'fail'@ if the given input
-- is not 32 bytes in length.
createKeypairFromSeed :: ByteString             -- ^ Two byte seed input
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

-- | Calculate the @'PublicKey'@ for a given @'SecretKey'@.
toPublicKey :: SecretKey -- ^ Any valid @'SecretKey'@
            -> PublicKey -- ^ Corresponding @'PublicKey'@
toPublicKey = PublicKey . S.drop prefixBytes  . unSecretKey
  where prefixBytes = cryptoSignSECRETKEYBYTES - cryptoSignPUBLICKEYBYTES

--------------------------------------------------------------------------------
-- Main API

-- | Sign a message with a particular @'SecretKey'@. Note that the resulting
-- signed message contains both the message itself, and the signature
-- attached. If you only want the signature of a given input string,
-- please see @'sign''@.
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

-- | A @'Signature'@ which is detached from the message it signed.
newtype Signature = Signature { unSignature :: ByteString }
        deriving (Eq, Show, Ord)

-- | Sign a message with a particular @'SecretKey'@, only returning the
-- @'Signature'@ without the message.
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
