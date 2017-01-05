module Main
       ( main -- :: IO ()
       ) where
import           Control.Applicative
import           Control.Monad
import           Data.List            ( isInfixOf )
import           System.Directory
import           System.FilePath

import           System.FilePath.Find ( find, directory, extension, (==?), (&&?) )
import           Test.DocTest

main :: IO ()
main = allSources >>= \sources -> doctest ("-isrc":sources)

allSources :: IO [FilePath]
allSources = liftM2 (++) (getHsFiles "src") (getCObjFiles ".")

getHsFiles :: FilePath -> IO [FilePath]
getHsFiles = find (return True) (extension ==? ".hs")

getCObjFiles :: FilePath -> IO [FilePath]
getCObjFiles = find (return True) (isObj &&? isCorrectDir) where
  isObj = extension ==? ".o"
  isCorrectDir = isInfixOf "build/src/cbits" `liftM` directory
