{-# LANGUAGE CPP #-}
module Main
       ( main -- :: IO ()
       ) where

import Criterion.Main
import Crypto.Sign.Ed25519

import Control.DeepSeq
import qualified Data.ByteString as B

--------------------------------------------------------------------------------

#if !MIN_VERSION_bytestring(0,10,0)
instance NFData ByteString
#endif

instance NFData SecretKey
instance NFData PublicKey

--------------------------------------------------------------------------------

main :: IO ()
main = do
  keys@(pk,sk) <- createKeypair
  let dummy = B.pack [1..512]
      msg = sign sk dummy
  defaultMain
    [ bench "createKeypair" $ nfIO createKeypair
    , bench "sign"          $ nf (sign sk)        dummy
    , bench "verify"        $ nf (verify pk)      msg
    , bench "roundtrip"     $ nf (signBench keys) dummy
    ]

signBench :: (PublicKey, SecretKey) -> B.ByteString -> Bool
signBench (pk, sk) xs = verify pk (sign sk xs)
