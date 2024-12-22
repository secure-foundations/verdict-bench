{-# LANGUAGE OverloadedStrings #-}

import System.Posix.Env.ByteString
import Distribution.Simple
import Data.Maybe
import Text.StringPrep (runStringPrep)
import Text.StringPrep.Profiles (namePrepProfile)
import Data.Typeable

main = do
    inpt <- getArgs
    let out = fromMaybe "ERROR!!" (runStringPrep (namePrepProfile True) (head inpt))
    putStrLn(show(out))
