{-# LANGUAGE TemplateHaskell #-}
module Main
       ( main  -- :: IO ()
       ) where
import Prelude as Prelude
import Data.List as List
import Data.Maybe
import Data.Function
import Control.Monad
import Control.DeepSeq
import Debug.Trace

import Test.Tasty
import Test.Tasty.TH
import Test.Tasty.HUnit as HUnit

--------------------------------------------------------------------------------
-- Driver

main :: IO ()
main = $(defaultMainGenerator)
