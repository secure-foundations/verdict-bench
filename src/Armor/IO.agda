{-# OPTIONS --guardedness #-}

import      Armor.Foreign.ByteString as ByteString
open import Armor.Foreign.Time
open import Armor.Prelude
import      System.Exit

module Armor.IO where

{-# FOREIGN GHC import qualified Data.ByteString as ByteString #-}
{-# FOREIGN GHC import qualified System.Environment #-}
{-# FOREIGN GHC import qualified System.IO #-}
{-# FOREIGN GHC import qualified Data.Text          #-}
{-# FOREIGN GHC import qualified Data.Text.IO as TIO #-}
{-# FOREIGN GHC import           Data.Time.Clock #-}
{-# FOREIGN GHC import           Data.Time.Clock.POSIX (getPOSIXTime) #-}

module Primitive where
  open import IO.Primitive
  postulate
    Handle IOMode  : Set

    readMode : IOMode
    openFile : String → IOMode → IO Handle

    getArgs : IO (List String)
    stderr  : Handle
    hPutStrLn : Handle → String → IO ⊤

    getContents    : IO ByteString.ByteString
    hGetContents   : Handle → IO ByteString.ByteString
    getCurrentTime : IO UTCTime

    getCurrentTimeMicroseconds : IO ℕ

{-# COMPILE GHC Primitive.Handle = type System.IO.Handle #-}
{-# COMPILE GHC Primitive.IOMode = type System.IO.IOMode #-}

{-# FOREIGN GHC
aeresOpenFile :: Data.Text.Text -> System.IO.IOMode -> IO System.IO.Handle
aeresOpenFile path mode = System.IO.openFile (Data.Text.unpack path) mode
#-}

{-# COMPILE GHC Primitive.readMode = System.IO.ReadMode #-}
{-# COMPILE GHC Primitive.openFile = aeresOpenFile #-}

{-# COMPILE GHC Primitive.getArgs = fmap Data.Text.pack <$> System.Environment.getArgs #-}
{-# COMPILE GHC Primitive.stderr = System.IO.stderr #-}
{-# COMPILE GHC Primitive.hPutStrLn = TIO.hPutStrLn #-}

{-# COMPILE GHC Primitive.getContents = ByteString.getContents #-}
{-# COMPILE GHC Primitive.hGetContents = ByteString.hGetContents #-}
{-# COMPILE GHC Primitive.getCurrentTime = getCurrentTime #-}
{-# COMPILE GHC Primitive.getCurrentTimeMicroseconds = fmap (round . (* 1e6)) getPOSIXTime #-}

open import IO
open System.Exit public using (exitFailure ; exitSuccess)

openFile : String → Primitive.IOMode → IO Primitive.Handle
openFile path mode = lift (Primitive.openFile path mode)

getArgs : IO (List String)
getArgs = lift Primitive.getArgs

putStrLnErr : String → IO (Level.Lift Level.zero ⊤)
putStrLnErr str = Level.lift IO.<$> (lift (Primitive.hPutStrLn Primitive.stderr str))

getByteStringContents : IO ByteString.ByteString
getByteStringContents = lift Primitive.getContents

hGetByteStringContents : Primitive.Handle → IO ByteString.ByteString
hGetByteStringContents h = lift (Primitive.hGetContents h)

getCurrentTime : IO UTCTime
getCurrentTime = lift Primitive.getCurrentTime

getCurrentTimeMicroseconds : IO ℕ
getCurrentTimeMicroseconds = lift Primitive.getCurrentTimeMicroseconds

postulate stringToNat : String → Maybe ℕ

{-# COMPILE GHC stringToNat = \s -> case reads (Data.Text.unpack s) of
      [(n, "")] -> Just n; _ -> Nothing #-}

-- open import Agda.Builtin.Nat using (Nat)
-- open import Foreign.Haskell using (Pair)

-- data Clock : Set where
--   monotonic realTime processCPUTime : Clock
--   threadCPUTime monotonicRaw bootTime : Clock
--   monotonicCoarse realTimeCoarse : Clock

-- {-# COMPILE GHC Clock = data Clock (Monotonic | Realtime | ProcessCPUTime
--                                    | ThreadCPUTime | MonotonicRaw | Boottime
--                                    | MonotonicCoarse | RealtimeCoarse )
-- #-}

-- postulate getTimePrim : Clock → IO (Pair Nat Nat)

-- {-# FOREIGN GHC import System.Clock  #-}
-- {-# FOREIGN GHC import Data.Function #-}
-- {-# COMPILE GHC getTimePrim = fmap (\ (TimeSpec a b) -> ((,) `on` fromIntegral) a b) . getTime #-}

-- record Time : Set where
--   constructor mkTime
--   field seconds     : ℕ
--         nanoseconds : ℕ
-- open Time public

-- ------------------------------------------------------------------------
-- -- Reading the clock

-- getTime : Clock → IO Time
-- getTime c = do
--   (a , b) ← lift (getTimePrim c)
--   pure $ mkTime a b

-- diff : Time → Time → Time
-- diff (mkTime ss sns) (mkTime es ens) =
--   if ens <ᵇ sns
--   then mkTime (es ∸ suc ss) ((1000000000 + ens) ∸ sns)
--   else mkTime (es ∸ ss) (ens ∸ sns)

-- show : Time →   -- Time in seconds and nanoseconds
--        Fin 10 → -- Number of decimals to show
--                 -- (in [0,9] because we are using nanoseconds)
--        String
-- show (mkTime s ns) prec = secs ++ "s" ++ padLeft '0' decimals nsecs where
--   decimals = toℕ prec
--   secs     = ℕ.show s
--   prf      = ℕ.m^n≢0 10 (9 ∸ decimals)
--   nsecs    = ℕ.show ((ns / (10 ^ (9 ∸ decimals))) {{prf}})
