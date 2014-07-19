{-# LANGUAGE DeriveDataTypeable #-}
module Main where

import Options.Applicative
import Data.Monoid
import Data.List
import Vault.Crypto
import Crypto.Random.Entropy
import Data.Byteable
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.UTF8 as UTF8
import System.IO

data Command =
      Encrypt
        { encryptFile :: String
        }
    | Decrypt
        { decryptFile :: String
        }
    deriving (Show,Eq)

commands =
    [ ("encrypt", cmdEncrypt, "encrypt a file")
    , ("decrypt", cmdDecrypt, "decrypt a file")
    ]
  where cmdEncrypt = Encrypt
            <$> file
        cmdDecrypt = Decrypt
            <$> file
        file = argument Just (metavar "<file>")

getOptions :: IO Command
getOptions = execParser (info (parseCArgs <**> helper) idm)
  where parseCArgs = subparser $ mconcat $ map (\(name, v, desc) -> command name (info v (progDesc desc))) commands

askString :: String -> IO B.ByteString
askString h = do
    putStrLn h
    hSetEcho stdout False
    hFlush stdout
    d <- getLine
    hSetEcho stdout True
    return $ UTF8.fromString d

runCommand (Encrypt file) = do
    key   <- pbkdf <$> askString "passphrase> "
    nonce <- toBytes <$> getEntropy 8
    L.readFile file >>= L.writeFile (file ++ ".crypt") . encrypt key nonce

runCommand (Decrypt file) = do
    key <- pbkdf <$> askString "passphrase> "
    let outFile =
                if ".crypt" `isSuffixOf` file
                        then take (length file - 6) file
                        else file ++ ".decrypt"
    L.readFile file >>= L.writeFile outFile . decrypt key

main = getOptions >>= runCommand
