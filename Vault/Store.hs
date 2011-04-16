-- |
-- Module      : Vault.Store
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Vault.Store
	(
	  Version
	, version1
	, Structured(..)
	-- * structured from/to bytes
	, encodeStructured
	, decodeStructured
	) where

import Control.Monad
import Control.Applicative ((<$>))
import Data.Serialize
import Data.Serialize.Put (runPut, putWord32le, putWord8, putByteString)
import Data.Serialize.Get (runGet, getWord32le, getWord8, getByteString, skip, remaining)
import Data.Word
import Data.Maybe
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

type Version = Int

version1 :: Version
version1 = 1

-- | Structured is the internal representation between the secret and the
-- on-disk representation.
--
-- * version:        w8
-- * use-passphrase: w8
-- * dummy:          w8
-- * dummy:          w8
-- * encrypted-data: remaining bytes
data Structured = Structured
	{ suVersion     :: Version
	, usePassphrase :: Bool
	, suEncrypted   :: ByteString
	} deriving (Eq)

putBool True  = putWord8 1
putBool False = putWord8 0
getBool = pBool <$> getWord8
	where
		pBool 0 = False
		pBool 1 = True
		pBool _ = error "bool with wrong value"

putStructuredVer1 s = do
	putBool (usePassphrase s)
	putWord8 0
	putWord8 0
	putByteString $ suEncrypted s

getStructuredVer1 = do
	usePP     <- getBool
	_         <- getWord8
	_         <- getWord8
	encrypted <- remaining >>= getByteString
	return $ Structured
		{ suVersion     = 1
		, usePassphrase = usePP
		, suEncrypted   = encrypted
		}

magic = [0x4C,0x4F,0x43,0x6B]

instance Serialize Structured where
	put s = do
		mapM putWord8 magic
		putWord8 $ fromIntegral $ suVersion s
		case suVersion s of
			1 -> putStructuredVer1 s
			_ -> error "unknown encoding version"
	get = do
		w <- replicateM 4 getWord8
		when (w /= magic) $ error "not a vault file"
		ver <- getWord8
		case ver of
			1 -> getStructuredVer1
			_ -> error "unknown encoding version"

encodeStructured :: Structured -> ByteString
encodeStructured s = encode s

decodeStructured :: ByteString -> Structured
decodeStructured d = case decode d of
	Left err -> error ("error decoding vault file: " ++ show err)
	Right x  -> x
