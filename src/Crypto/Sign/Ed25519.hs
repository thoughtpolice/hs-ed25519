{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Sign.Ed25519
-- Copyright   : (c) Austin Seipp 2013
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
         PublicKey(..)       -- :: *
       , SecretKey(..)       -- :: *
       , createKeypair       -- :: IO (PublicKey, SecretKey)
         -- * Signing and verifying messages
       , sign                -- :: SecretKey -> ByteString -> ByteString
       , verify              -- :: PublicKey -> ByteString -> Bool
         -- * Detached signatures
       , Signature(..)       -- :: *
       , sign'               -- :: SecretKey -> ByteString -> Signature
       , verify'             -- :: PublicKey -> ByteString -> Signature -> Bool
       ) where
import           Foreign.C.Types
import           Foreign.ForeignPtr       (withForeignPtr)
import           Foreign.Marshal.Alloc    (alloca)
import           Foreign.Ptr
import           Foreign.Storable

import           System.IO.Unsafe         (unsafePerformIO)

import           Data.ByteString          as S
import           Data.ByteString.Internal as SI
import           Data.ByteString.Unsafe   as SU
import           Data.Word

--------------------------------------------------------------------------------

-- | A 'SecretKey' created by 'createKeypair'. Be sure to keep this
-- safe!
newtype SecretKey = SecretKey { unSecretKey :: ByteString }
        deriving (Eq, Show, Ord)

-- | A 'PublicKey' created by 'createKeypair'.
newtype PublicKey = PublicKey { unPublicKey :: ByteString }
        deriving (Eq, Show, Ord)

-- | Randomly generate a public and private key for doing
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

--------------------------------------------------------------------------------
-- Main API

-- | Sign a message with a particular 'SecretKey'.
sign :: SecretKey
     -- ^ Signers secret key
     -> ByteString
     -- ^ Input message
     -> ByteString
     -- ^ Resulting signed message
sign (SecretKey sk) xs =
  unsafePerformIO . SU.unsafeUseAsCStringLen xs $ \(mstr,mlen) ->
    SU.unsafeUseAsCString sk $ \psk ->
      SI.createAndTrim (mlen+cryptoSignBYTES) $ \out ->
        alloca $ \smlen -> do
          _ <- (c_crypto_sign out smlen mstr (fromIntegral mlen) psk)
          fromIntegral `fmap` peek smlen
{-# INLINE sign #-}

-- | Verifies a signed message against a 'PublicKey'.
verify :: PublicKey
       -- ^ Signers public key
       -> ByteString
       -- ^ Signed message
       -> Bool
       -- ^ Verification check
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

-- | A 'Signature' which is detached from the message it signed.
newtype Signature = Signature { unSignature :: ByteString }
        deriving (Eq, Show, Ord)

-- | Sign a message with a particular 'SecretKey', only returning the
-- signature without the message.
sign' :: SecretKey
      -- ^ Signers secret key
      -> ByteString
      -- ^ Input message
      -> Signature
      -- ^ Message signature, without the message
sign' sk xs =
  let sm = sign sk xs
      l  = S.length sm
  in Signature $! S.take (l - S.length xs) sm
{-# INLINE sign' #-}

-- | Verify a message with a detached 'Signature', for a given
-- 'PublicKey'.
verify' :: PublicKey
        -- ^ Signers public key
        -> ByteString
        -- ^ Input message, without signature
        -> Signature
        -- ^ Message signature
        -> Bool
verify' pk xs (Signature sig) = verify pk (sig `S.append` xs)
{-# INLINE verify' #-}

--
-- FFI signature binding
--

cryptoSignSECRETKEYBYTES :: Int
cryptoSignSECRETKEYBYTES = 64

cryptoSignPUBLICKEYBYTES :: Int
cryptoSignPUBLICKEYBYTES = 32

cryptoSignBYTES :: Int
cryptoSignBYTES = 64

foreign import ccall unsafe "ed25519_sign_keypair"
  c_crypto_sign_keypair :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "ed25519_sign"
  c_crypto_sign :: Ptr Word8 -> Ptr CULLong ->
                   Ptr CChar -> CULLong -> Ptr CChar -> IO CULLong

foreign import ccall unsafe "ed25519_sign_open"
  c_crypto_sign_open :: Ptr Word8 -> Ptr CULLong ->
                        Ptr CChar -> CULLong -> Ptr CChar -> IO CInt
