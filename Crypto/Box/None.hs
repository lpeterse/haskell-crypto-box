{-# LANGUAGE TypeFamilies #-}
module Crypto.Box.None (
    None
  , PublicKey (..)
  , SecretKey
  , Factory
  , Box
  ) where

import qualified Crypto.Box as CB

data None

data PublicKey
   = PublicKey String
   deriving (Eq, Ord, Show)

data SecretKey
   = SecretKey String
   deriving (Eq, Ord, Show)

data Factory
   = Factory SecretKey
   deriving (Eq, Ord, Show)

data Box
   = Box Factory PublicKey
   deriving (Eq, Ord, Show)

instance CB.CryptoBox None where
  type PublicKey None = PublicKey
  type SecretKey None = SecretKey
  type Factory   None = Factory
  type Box       None = Box

  createFactory       = return . Factory
  createRandomFactory = return $ Factory (SecretKey "4; // chosen by fair dice roll.")

  box f k             = Box f k

  encrypt b message   = return message
  decrypt b cipher    = Just cipher

  publicKey (Factory (SecretKey s))
                      = PublicKey (reverse s)