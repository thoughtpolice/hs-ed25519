module Main where

import Data.Monoid
import Control.Monad
import Language.Haskell.HLint
import System.Environment
import System.Exit

main :: IO ()
main = do
    args <- getArgs
    hints <- hlint $ ["src", "benchmarks", "tests",
                      "--cpp-define=HLINT"] `mappend` args
    unless (null hints) exitFailure
