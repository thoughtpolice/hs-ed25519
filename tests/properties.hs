{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE CPP #-}
module Main
       ( main -- :: IO ()
       ) where
import           Control.Monad
import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as S

import           Crypto.Sign.Ed25519

import           System.Environment       (getArgs)
import           Test.QuickCheck
import           Test.QuickCheck.Property (morallyDubiousIOProperty)
import           Text.Printf

--------------------------------------------------------------------------------
-- Orphans

instance Arbitrary ByteString where
  arbitrary = S.pack `liftM` arbitrary

instance Arbitrary SecretKey where
  arbitrary = SecretKey `liftM` arbitrary

instance Arbitrary PublicKey where
  arbitrary = PublicKey `liftM` arbitrary

--------------------------------------------------------------------------------
-- Signatures

keypairProp :: ((PublicKey, SecretKey) -> Bool) -> Property
keypairProp k = morallyDubiousIOProperty $ k `liftM` createKeypair

roundtrip :: ByteString -> Property
roundtrip xs
  = keypairProp $ \(pk,sk) -> verify pk (sign sk xs)

roundtrip' :: ByteString -> Property
roundtrip' xs
  = keypairProp $ \(pk,sk) -> dverify pk xs (dsign sk xs)

-- Generally the signature format is '<signature><original message>'
-- and <signature> is of a fixed length (crypto_sign_BYTES), which in
-- ed25519's case is 64. @'dsign'@ drops the message appended at the
-- end, so we just make sure we have constant length signatures.
signLength :: (ByteString,ByteString) -> Property
signLength (xs,xs2)
  = keypairProp $ \(_,sk) ->
      let s1 = unSignature $ dsign sk xs
          s2 = unSignature $ dsign sk xs2
      in S.length s1 == S.length s2

-- ed25519 has a sig length of 64
signLength2 :: ByteString -> Property
signLength2 xs
  = keypairProp $ \(_,sk) ->
      (64 == S.length (unSignature $ dsign sk xs))

--------------------------------------------------------------------------------
-- Driver

main :: IO ()
main = do
  args <- getArgs
  let n = if null args then 100 else read (head args) :: Int
  (results, passed) <- runTests n
  printf "Passed %d tests!\n" (sum passed)
  unless (and results) (fail "Not all tests passed!")

runTests :: Int -> IO ([Bool], [Int])
runTests ntests = fmap unzip . forM (tests ntests) $ \(s, a) ->
  printf "%-40s: " s >> a

tests :: Int -> [(String, IO (Bool,Int))]
tests ntests =
  [ ("Signature roundtrip",            wrap roundtrip)
  , ("Detached signature roundtrip",   wrap roundtrip')
  , ("Detached signature length",      wrap signLength)
  , ("Detached signature length (#2)", wrap signLength2)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap prop = do
      r <- quickCheckWithResult stdArgs{maxSuccess=ntests} prop
      case r of
        Success n _ _           -> return (True, n)
        GaveUp  n _ _           -> return (True, n)
#if MIN_VERSION_QuickCheck(2,7,0)
        Failure n _ _ _ _ _ _ _ _ _ -> return (False, n)
#elif MIN_VERSION_QuickCheck(2,6,0)
        Failure n _ _ _ _ _ _ _ -> return (False, n)
#else
        Failure n _ _ _ _ _ _   -> return (False, n)
#endif
        _                       -> return (False, 0)
