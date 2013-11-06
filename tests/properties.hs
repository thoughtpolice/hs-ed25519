{-# LANGUAGE TemplateHaskell #-}
module Main
       ( main  -- :: IO ()
       ) where
import Prelude
import Data.List as List
import Data.Maybe
import Data.Function
import Control.Monad
import Control.DeepSeq
import Debug.Trace

import Test.Tasty
import Test.Tasty.TH
import Test.Tasty.QuickCheck as QC
import Test.QuickCheck.Property

import Data.ByteString as S
import Crypto.Sign.Ed25519

--------------------------------------------------------------------------------
-- Orphans

instance Arbitrary ByteString where
  arbitrary = pack `liftM` arbitrary

instance Arbitrary SecretKey where
  arbitrary = SecretKey `liftM` arbitrary

instance Arbitrary PublicKey where
  arbitrary = PublicKey `liftM` arbitrary

--------------------------------------------------------------------------------
-- Signatures

keypairProp :: ((PublicKey, SecretKey) -> Bool) -> Property
keypairProp k = morallyDubiousIOProperty $ k `liftM` createKeypair

prop_sign_verify :: ByteString -> Property
prop_sign_verify xs
  = keypairProp $ \(pk,sk) -> verify pk (sign sk xs)

-- Generally the signature format is '<signature><original message>'
-- and <signature> is of a fixed length (crypto_sign_BYTES), which in
-- ed25519's case is 64. sign' drops the message appended at the end,
-- so we just make sure we have constant length signatures.
prop_sign'_length :: ByteString -> ByteString -> Property
prop_sign'_length xs xs2
  = keypairProp $ \(pk,sk) ->
      let s1 = unSignature $ sign' sk xs
          s2 = unSignature $ sign' sk xs2
      in S.length s1 == S.length s2

-- ed25519 has a sig length of 64
prop_sign'_length2 :: ByteString -> Property
prop_sign'_length2 xs
  = keypairProp $ \(pk,sk) ->
      (64 == S.length (unSignature $ sign' sk xs))

prop_verify' :: ByteString -> Property
prop_verify' xs
  = keypairProp $ \(pk,sk) ->
      verify' pk xs (sign' sk xs)

--------------------------------------------------------------------------------
-- Driver

main :: IO ()
main = $(defaultMainGenerator)
