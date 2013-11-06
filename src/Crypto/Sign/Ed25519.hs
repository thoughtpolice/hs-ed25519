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
-- This module provides bindings to the ed25519 signing system,
-- including detached signatures. The underlying implementation uses
-- the @ref10@ implementation of ed25519 from SUPERCOP, and should be
-- relatively fast.
--
-- For more information (including how to get a copy of the software)
-- visit <http://ed25519.cr.yp.to>.
--
module Crypto.Sign.Ed25519
       ( -- * Keypair creation
         createKeypair                 -- :: IO (ByteString, ByteString)
         -- * Signing and verifying messages
       , sign                          -- :: ByteString -> ByteString -> ByteString
       , verify                        -- :: ByteString -> ByteString -> Maybe ByteString
       , Signature(..)                 -- :: *
       , sign'                         -- :: ByteString -> ByteString -> Signature
       , verify'                       -- :: ByteString -> ByteString -> Signature -> Maybe ByteString
       ) where
import           Control.Monad            (liftM, void)
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

-- | A 'Signature'. Used with 'sign\'' and 'verify\''.
newtype Signature = Signature { unSignature :: ByteString }
        deriving (Eq, Show, Ord)

-- | Randomly generate a public and private key for doing
-- authenticated signing and verification.
createKeypair :: IO (ByteString, ByteString)
createKeypair = do
  pk <- SI.mallocByteString cryptoSignPUBLICKEYBYTES
  sk <- SI.mallocByteString cryptoSignSECRETKEYBYTES

  void . withForeignPtr pk $ \ppk ->
    void . withForeignPtr sk $ \psk ->
      c_crypto_sign_keypair ppk psk

  return (SI.fromForeignPtr pk 0 cryptoSignPUBLICKEYBYTES,
          SI.fromForeignPtr sk 0 cryptoSignSECRETKEYBYTES)

-- | Sign a message with a particular 'SecretKey'.
sign :: ByteString
     -- ^ Signers secret key
     -> ByteString
     -- ^ Input message
     -> ByteString
     -- ^ Resulting signed message
sign sk xs =
  unsafePerformIO . SU.unsafeUseAsCStringLen xs $ \(mstr,mlen) ->
    SU.unsafeUseAsCString sk $ \psk ->
      SI.createAndTrim (mlen+cryptoSignBYTES) $ \out ->
        alloca $ \smlen -> do
          void (c_crypto_sign out smlen mstr (fromIntegral mlen) psk)
          fromIntegral `liftM` peek smlen
{-# INLINEABLE sign #-}

-- | Sign a message with a particular 'SecretKey', only returning the signature
-- without the message.
sign' :: ByteString
      -- ^ Signers secret key
      -> ByteString
      -- ^ Input message
      -> Signature
      -- ^ Message signature, without the message
sign' sk xs =
  let sm = sign sk xs
      l  = S.length sm
  in Signature $! S.take (l - S.length xs) sm
{-# INLINEABLE sign' #-}

-- | Verifies a signed message with a 'PublicKey'. Returns @Nothing@ if
-- verification fails, or @Just xs@ where @xs@ is the original message if it
-- succeeds.
verify :: ByteString
       -- ^ Signers public key
       -> ByteString
       -- ^ Signed message
       -> Maybe ByteString
       -- ^ Verification check
verify pk xs =
  unsafePerformIO . SU.unsafeUseAsCStringLen xs $ \(smstr,smlen) ->
    SU.unsafeUseAsCString pk $ \ppk ->
      alloca $ \pmlen -> do
        out <- SI.mallocByteString smlen

        r <- withForeignPtr out $ \pout ->
               c_crypto_sign_open pout pmlen smstr (fromIntegral smlen) ppk

        if r /= 0 then return Nothing
          else do
            l <- peek pmlen
            return . Just $ SI.fromForeignPtr out 0 (fromIntegral l)
{-# INLINEABLE verify #-}

-- | Verify that a message came from someone\'s 'PublicKey'
-- using an input message and a signature derived from 'sign\''
verify' :: ByteString
        -- ^ Signers\' public key
        -> ByteString
        -- ^ Input message, without signature
        -> Signature
        -- ^ Message signature
        -> Maybe ByteString
verify' pk xs (Signature sig) = verify pk (sig `S.append` xs)
{-# INLINEABLE verify' #-}

--
-- FFI signature binding
--

cryptoSignSECRETKEYBYTES :: Int
cryptoSignSECRETKEYBYTES = 64

cryptoSignPUBLICKEYBYTES :: Int
cryptoSignPUBLICKEYBYTES = 32

cryptoSignBYTES :: Int
cryptoSignBYTES = 64

foreign import ccall unsafe "crypto_sign_keypair"
  c_crypto_sign_keypair :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_sign"
  c_crypto_sign :: Ptr Word8 -> Ptr CULLong ->
                   Ptr CChar -> CULLong -> Ptr CChar -> IO CULLong

foreign import ccall unsafe "crypto_sign_open"
  c_crypto_sign_open :: Ptr Word8 -> Ptr CULLong ->
                        Ptr CChar -> CULLong -> Ptr CChar -> IO CInt
