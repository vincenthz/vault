-- |
-- Module      : Vault.Crypto
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Vault.Crypto
	( encrypt
	, decrypt
	, enPassphrase
	, dePassphrase
	, hash
	) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import qualified Crypto.Cipher.AES as AES
import Crypto.Hash.SHA512 (hash)

import Text.Printf
import Data.Bits

-- | EssivCBC is a CBC mode where the IV vectors are determined by a ESSIV like algorithm
encrypt key fIV b
	| B.length b `mod` 16 /= 0 = error ("encrypt length error: " ++ show (B.length b))
	| otherwise = B.concat $ loop fIV $ zip [0..] $ reverse $ chunks 16 b
	where
		loop _  []     = []
		loop iv (x:xs) =
			let e = encryptOne iv x in
			e : loop e xs

		encryptOne iv (n, b) = AES.encrypt k x
			where
				x      = bxor b $ bxor eiv iv
				eiv    = hash (bxor key bnRepr)
				bnRepr = B.replicate 32 (fromIntegral $ n + 1)

		(Right k) = AES.initKey256 key

decrypt key fIV b
	| B.length b `mod` 16 /= 0 = error ("decrypt length error: " ++ show (B.length b))
	| otherwise = B.concat $ reverse $ loop fIV $ zip [0..] $ chunks 16 b
	where
		loop _  []     = []
		loop iv ((n,b):xs) =
			let e = decryptOne iv (n,b) in
			e : loop b xs

		decryptOne iv (n, b) = bxor eiv $ bxor iv $ AES.decrypt k b
			where
				eiv    = hash (bxor key bnRepr)
				bnRepr = B.replicate 32 (fromIntegral $ n + 1)

		(Right k) = AES.initKey256 key

enPassphrase pp = AES.encryptCBC key (B.replicate 16 0)
	where (Right key) = AES.initKey256 $ hash pp

dePassphrase pp = AES.encryptCBC key (B.replicate 16 0)
	where (Right key) = AES.initKey256 $ hash pp

bxor a b = B.pack $ B.zipWith xor a b

chunks :: Int -> ByteString -> [ByteString]
chunks sz b
	| B.length b < sz  = error ("chunkify partial packet: " ++ show (B.length b))
	| B.length b == sz = [b]
	| otherwise        = b1 : chunks sz b2
		where (b1, b2) = B.splitAt sz b
