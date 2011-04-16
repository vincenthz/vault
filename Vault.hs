-- |
-- Module      : Vault
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Vault is a library to store secrets securely.
--
module Vault
	( Secret
	, Key
	, Salt
	, Passphrase
	, Version

	-- * random helper
	, version1

	-- * wrap types
	, makeSecret
	, getSecret
	, makeKey
	, makePassphrase
	, makeSalt
	, usePassphrase

	-- * main functions
	, storeKey
	, unstoreKey
	, storeSecret
	, unstoreSecret

	-- * usual paths
	, module Vault.Path
	) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8, encodeUtf8)

import Control.Applicative ((<$>))
import Control.Arrow (first)
import Control.Monad

import Data.Maybe (isJust)
import Data.Word
import Data.Bits

import Crypto.Random
import Vault.Crypto
import Vault.Path
import Vault.Store

import Data.Serialize.Put (runPut, putWord32le, putWord8, putByteString)
import Data.Serialize.Get (runGet, getWord32le, getWord8, getByteString, skip, remaining)

{-| Key represent a cryptographic key for the AES 256 bit cipher -}
newtype Key = Key { unwrapKey :: ByteString } deriving (Eq)

{-| Salt is used to introduce some (known) aleas into the encryption -}
newtype Salt = Salt { unwrapSalt :: ByteString } deriving (Eq)

{-| Secret represent something to store. -}
newtype Secret = Secret { unwrapSecret :: ByteString } deriving (Eq)

{-| Passphrase is used to unlock stored Key -}
newtype Passphrase = Passphrase { unwrapPP :: ByteString } deriving (Eq)

encodeString = encodeUtf8 . T.pack
decodeString = T.unpack . decodeUtf8

makeSecret :: String -> Secret
makeSecret = Secret . encodeString

getSecret :: Secret -> String
getSecret = decodeString . unwrapSecret

makeSalt :: ByteString -> Salt
makeSalt b
	| B.length b /= 16 = error "salt size need to be 16 bytes"
	| otherwise        = Salt b

makeKey :: ByteString -> Key
makeKey b
	| B.length b /= 32 = error "key size need to be 32 bytes"
	| otherwise        = Key b

makePassphrase :: String -> Passphrase
makePassphrase = Passphrase . encodeString

genBytesNoErr :: CryptoRandomGen g => Int -> g -> (ByteString, g)
genBytesNoErr len rng = case genBytes len rng of 
	Left err -> error ("error during random bytes generation: " ++ show err)
	Right z  -> z

encryptSecret :: CryptoRandomGen g => Key -> Salt -> Secret -> g -> (ByteString, g)
encryptSecret key salt secret rng = (B.concat [unwrapSalt salt,encrypted], rng')
	where
		encrypted     = encrypt (unwrapKey key) (unwrapSalt salt) toEnc
		toEnc         = B.concat [putW32 (fromIntegral padlen),hash $ unwrapSecret secret,unwrapSecret secret,pad]
		(pad, rng'')  = genBytesNoErr padlen rng'
		(extra, rng') = first (fromIntegral . B.head) $ genBytesNoErr 1 rng
		padlen        = (16 - seclen `mod` 16) - 4 + 16 * (extra `setBit` 7)
		seclen        = B.length $ unwrapSecret secret
		putW32        = runPut . putWord32le

decryptSecret :: Key -> ByteString -> Secret
decryptSecret k b =
	case runGet doGet $ decrypt (unwrapKey k) iv encrypted of
		Left err -> error ("data error: " ++ err)
		Right (h,x) -> if hash x == h
			then Secret x
			else error "hash mismatch"
	where
		doGet = do
			padlen <- fromIntegral <$> getWord32le
			h      <- getByteString 64
			rem    <- remaining
			s      <- getByteString (rem - padlen)
			return (h,s)
		(iv, encrypted) = B.splitAt 16 b

serializeKey :: Key -> Secret
serializeKey k = Secret $ unwrapKey k

unserializeKey :: Secret -> Key
unserializeKey s = Key $ unwrapSecret s

storeKey :: Key -> Maybe Passphrase -> ByteString
storeKey k p =
	let secret = unwrapSecret $ serializeKey k in
	encodeStructured $ case p of
		Nothing -> Structured 1 False secret
		Just pp -> Structured 1 True (enPassphrase (unwrapPP pp) secret)

unstoreKey :: ByteString -> (IO Passphrase) -> IO Key
unstoreKey b askpass = do
	let s = decodeStructured b
	case usePassphrase s of
		False -> return $ Key $ suEncrypted s
		True  -> askpass >>= \pass -> return $ Key $ dePassphrase (unwrapPP pass) $ suEncrypted s

storeSecret :: CryptoRandomGen g => Key -> Salt -> Secret -> g -> (ByteString, g)
storeSecret key salt secret rng = (encodeStructured $ Structured 1 False encrypted, rng')
	where
		(encrypted, rng') = encryptSecret key salt secret rng

unstoreSecret :: Key -> ByteString -> Secret
unstoreSecret key b = 
	let s = decodeStructured b in
	decryptSecret key (suEncrypted s)
