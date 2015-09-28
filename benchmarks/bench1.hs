{-# LANGUAGE CPP #-}
module Main
       ( main -- :: IO ()
       ) where

import Criterion.Main
import Crypto.Sign.Ed25519

import Data.Maybe (fromJust)
import Control.DeepSeq
import qualified Data.ByteString as B

--------------------------------------------------------------------------------

#if !MIN_VERSION_bytestring(0,10,0)
instance NFData B.ByteString
#endif

instance NFData SecretKey
instance NFData PublicKey

--------------------------------------------------------------------------------

main :: IO ()
main = do
  -- Don't use `createKeypair`, since that will incur a ton of calls
  -- to the OS to generate randomness. Simply generate a bogus Ed25519
  -- seed instead.
  let seed         = B.pack [0..31]
      keys@(pk,sk) = fromJust (createKeypairFromSeed_ seed)

      -- Generate a dummy message to sign, and a signature to verify
      -- against.
      dummy = B.pack [0..255]
      msg = sign sk dummy
  defaultMain
    [ bench "deterministic key generation"   $ nf createKeypairFromSeed_ seed
    , bench "signing a 256 byte message"     $ nf (sign sk)              dummy
    , bench "verifying a signature"          $ nf (verify pk)            msg
    , bench "roundtrip 256-byte sign/verify" $ nf (signBench keys)       dummy
    ]

signBench :: (PublicKey, SecretKey) -> B.ByteString -> Bool
signBench (pk, sk) xs = verify pk (sign sk xs)
