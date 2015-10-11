module Main
       ( main -- :: IO ()
       ) where
import           Control.Applicative
import           Control.Monad
import           Data.List
import           System.Directory
import           System.FilePath

import           Test.DocTest

main :: IO ()
main = allSources >>= \sources -> doctest ("-isrc":sources)

allSources :: IO [FilePath]
allSources = liftM2 (++) (getFiles ".hs" "src")
                         (getFiles ".o" "dist/build/src/cbits")

getFiles :: String -> FilePath -> IO [FilePath]
getFiles ext root = filter (isSuffixOf ext) <$> go root
  where
    go dir = do
      (dirs, files) <- getFilesAndDirectories dir
      (files ++) . concat <$> mapM go dirs

getFilesAndDirectories :: FilePath -> IO ([FilePath], [FilePath])
getFilesAndDirectories dir = do
  c <- fmap (dir </>) . filter (`notElem` ["..", "."]) <$> getDirectoryContents dir
  (,) <$> filterM doesDirectoryExist c <*> filterM doesFileExist c
