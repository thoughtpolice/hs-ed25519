module Main
       ( main -- :: IO ()
       ) where
import           Control.Monad
import           Data.Monoid
import           Language.Haskell.HLint
import           System.Environment
import           System.Exit

import           System.FilePath.Find (find, fileName)

main :: IO ()
main = do
  args <- getArgs

  -- When we build, we might use cabal, stack, cabal new-build, etc..
  -- so find the cabal_macros.h file dynamically.
  macros <- find (return True) ((== "cabal_macros.h") <$> fileName) "."
  case macros of
    [] -> do
      putStrLn "Couldn't find cabal_macros.h!"
      exitFailure
    [cabal_macros] -> do
      hints <- hlint $ [ "src", "benchmarks", "tests"
                       , "--cpp-define=HLINT"
                       , "--cpp-file=" `mappend` cabal_macros
                       ] `mappend` args
      unless (null hints) exitFailure
    _ -> do
      putStrLn "I found more than one cabal_macros.h file?!?! Bailing!"
      exitFailure
