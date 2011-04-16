-- |
-- Module      : Vault.Path
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Vault.Path
	( VaultPath(..)
	, getStandardPaths
	, pathOfSecret
	) where

import System.Environment

data VaultPath = VaultPath
	{ pathRoot  :: FilePath
	, pathKey   :: FilePath
	, pathStore :: FilePath
	}

getStandardPaths :: IO VaultPath
getStandardPaths = do
	home <- getEnv "HOME"
	let root = home ++ "/" ++ ".vault"
	return $ VaultPath
		{ pathRoot  = root
		, pathKey   = root ++ "/" ++ "key"
		, pathStore = root ++ "/" ++ "store"
		}

pathOfSecret :: VaultPath -> String -> FilePath
pathOfSecret vp name = pathStore vp ++ "/" ++ name
