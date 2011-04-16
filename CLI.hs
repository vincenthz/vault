{-# LANGUAGE DeriveDataTypeable #-}
module Main where

import qualified Data.ByteString as B
import Crypto.Random
import qualified Crypto.Random.AESCtr as RNG
import Control.Applicative ((<$>))
import Vault
import System.Console.CmdArgs hiding (name)
import System.Environment
import System.Exit
import System.Directory
import System.Posix.Files
import System.IO
import Control.Monad

withTempRNG :: (RNG.AESRNG -> (a, RNG.AESRNG)) -> IO a
withTempRNG f = RNG.makeSystem >>= return . fst . f

ofRight (Left err) = error ("generation error: " ++ show err)
ofRight (Right x)  = x

askString :: String -> IO String
askString h = do
	putStr h
	hFlush stdout
	line <- getLine
	return line

askPassphrase :: IO Passphrase
askPassphrase = makePassphrase <$> askString "Enter passphrase: "

askMaybePassphrase :: IO (Maybe Passphrase)
askMaybePassphrase = do	
	s <- askString "Enter passphrase (Enter to skip): "
	if null s
		then return Nothing
		else return $ Just $ makePassphrase s

readMasterKey :: FilePath -> IO Key
readMasterKey path = do
	content <- B.readFile path
	unstoreKey content askPassphrase

writeMasterKey :: FilePath -> Key -> IO ()
writeMasterKey path content = do
	passphrase <- askMaybePassphrase
	B.writeFile path (storeKey content passphrase)

generateSalt :: IO Salt
generateSalt = makeSalt <$> withTempRNG (ofRight . genBytes 16)

writeSecret :: Key -> FilePath -> Secret -> IO ()
writeSecret key file secret = do
	salt <- generateSalt
	encrypted <- withTempRNG (storeSecret key salt secret)
	B.writeFile file encrypted

readSecret :: Key -> FilePath -> IO Secret
readSecret key file = unstoreSecret key <$> B.readFile file

exitNotInitialized = do
	putStrLn "error: vault is not initialized"
	exitFailure

checkSystemInitialized b = do
	vp <- getStandardPaths
	exist <- doesDirectoryExist (pathRoot vp)
	when (not exist) $ exitNotInitialized
	fm <- fileMode <$> getFileStatus (pathRoot vp)
	-- FIXME check fm permission is 0x00 !
	return vp

doMain (Init) = do
	vp  <- getStandardPaths

	exist <- doesDirectoryExist (pathRoot vp)

	when exist $ do
		putStrLn "vault is already initialized"
		exitSuccess
	
	createDirectory (pathRoot vp)
	setFileMode (pathRoot vp) ownerModes
	createDirectory (pathStore vp)
	setFileMode (pathStore vp) ownerModes

	key <- makeKey <$> withTempRNG (ofRight . genBytes 32)
	writeMasterKey (pathKey vp) key
	setFileMode (pathKey vp) ownerReadMode
	return ()

doMain (Create n) = do
	vp <- checkSystemInitialized True
	key <- readMasterKey (pathKey vp)

	realn <- if n == "" then askString "enter name: " else return n

	s1 <- askString "enter secret: "
	s2 <- askString "re-enter    : "
	when (s1 /= s2) $ error "aborting: secret are different, try again."

	let filepath = pathOfSecret vp realn
	let secret = makeSecret s1

	writeSecret key filepath secret
	putStrLn "secret stored succesfuly"
	return ()

doMain (List) = do
	vp <- checkSystemInitialized True
	l <- getDirectoryContents (pathStore vp)
	mapM_ putStrLn $ filter (not . flip elem [ ".", ".." ])  l

doMain (Read "") =
	error "need to specify which secret you want to read"

doMain (Read n) = do
	vp <- checkSystemInitialized True
	key <- readMasterKey (pathKey vp)
	let filepath = pathOfSecret vp n
	secret <- readSecret key filepath
	putStrLn $ getSecret secret
	return ()

data MainOpts =
	  Init {}
	| Create { name :: String }
	| Read   { name :: String }
	| List {}
	deriving (Show,Data,Typeable)

initMode = Init
	{
	} &= help "initialize vault"

createMode = Create
	{ name = def &= args
	} &= help "create a new secret"

readMode = Read
	{ name = def &= argPos 0
	} &= help "read a secret"

listMode = List
	{
	} &= help "list all secrets"

mode = cmdArgsMode $ modes [initMode, createMode, readMode, listMode]
	&= help "Store and read secret securely"
	&= program "vault"
	&= summary "vault 0.1"

main = cmdArgsRun mode >>= doMain
