import Vault

import Crypto.Random
import Test.QuickCheck
import Test.QuickCheck.Test
import System.IO
import Control.Applicative ((<$>))
import qualified Data.ByteString as B

fakeKey  = makeKey $ B.replicate 32 0xf
fakeSalt = makeSalt $ B.replicate 16 0x0

newtype FakeRNG = FakeRNG Int

instance CryptoRandomGen FakeRNG where
	newGen        = undefined
	genSeedLength = undefined
	reseed        = undefined
	genBytes i (FakeRNG z) = Right (B.replicate i (fromIntegral z), FakeRNG $ z+1)

genByteString :: Int -> Gen B.ByteString
genByteString i = B.pack <$> vector i

instance Arbitrary Secret where
	arbitrary = makeSecret <$> listOf arbitrary
instance Arbitrary Key where
	arbitrary = makeKey <$> genByteString 32
instance Arbitrary Salt where
	arbitrary = makeSalt <$> genByteString 16

instance Show Secret where
	show s = "Secret " ++ (show $ getSecret s)
instance Show Key where
	show = const "Key[..]"
instance Show Salt where
	show = const "Salt[..]"

prop_identity secret = unstoreSecret fakeKey encrypted == secret
	where
		(encrypted, _) = storeSecret fakeKey fakeSalt secret (FakeRNG 12)

prop_identityAll (key, salt, secret) = unstoreSecret key encrypted == secret
	where
		(encrypted, _) = storeSecret key salt secret (FakeRNG 12)

myQuickCheckArgs = stdArgs

run_test n t = putStr ("  " ++ n ++ " ... ") >> hFlush stdout >> quickCheckWith myQuickCheckArgs t

main = do
	run_test "identity" prop_identity
	run_test "identity-all" prop_identityAll
