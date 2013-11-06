module Main
       ( main -- :: IO ()
       ) where

import Criterion.Main
import Crypto.Sign.Ed25519

import qualified Data.ByteString as B

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

signBench :: (B.ByteString, B.ByteString) -> B.ByteString -> Bool
signBench (pk, sk) xs
  = let sm = sign sk xs
        v  = verify pk sm
    in maybe False (== xs) v
