-- |
-- Module      : Vault.Crypto
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE OverloadedStrings #-}
module Vault.Crypto
    ( encrypt
    , decrypt
    , pbkdf
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Internal as L

import Crypto.Hash (SHA512(..))
import qualified Crypto.Cipher.ChaCha as ChaCha
import qualified Crypto.KDF.PBKDF2 as PBKDF2

import Data.Bits

initSt key nonce = ChaCha.initialize 20 key nonce

encrypt key nonce input =
    let st = initSt key nonce
     in runLoop st input
  where runLoop st lbs = L.chunk nonce (loop st lbs)
        loop state lbs
            | L.null lbs = L.empty
            | otherwise   =
                let (l1,l2) = L.splitAt 4096 lbs 
                    (encrypted, nstate) = ChaCha.combine state (L.toStrict l1)
                 in L.chunk encrypted (loop nstate l2)

decrypt key = runDecrypt key
  where runDecrypt key lbs =
            let (nonce, lbs') = L.splitAt 8 lbs
                state = initSt key (L.toStrict nonce)
             in loop state lbs'
        loop state lbs
            | L.null lbs = L.empty
            | otherwise  =
                let (l1,l2) = L.splitAt 4096 lbs
                    (decrypted, nstate) = ChaCha.combine state (L.toStrict l1)
                 in L.chunk decrypted (loop nstate l2)

pbkdf password =
    PBKDF2.generate (PBKDF2.prfHMAC SHA512) (PBKDF2.Parameters password "salt-is-good" 6000 32)
