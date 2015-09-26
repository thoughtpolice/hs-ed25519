module Main where

import Data.Monoid
import Control.Monad
import Language.Haskell.HLint
import System.Environment
import System.Exit

main :: IO ()
main = do
    args <- getArgs
    hints <- hlint $ [ "src", "benchmarks", "tests"
                     , "--cpp-define=HLINT"
                     , "--cpp-file=dist/build/autogen/cabal_macros.h"
                     ] `mappend` args
    unless (null hints) exitFailure
