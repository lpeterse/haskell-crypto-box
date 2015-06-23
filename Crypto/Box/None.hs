{-# LANGUAGE TypeFamilies #-}
module Crypto.Box.None (
    None
  , PublicKey (..)
  , SecretKey
  , BoxFactory
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

data BoxFactory
   = BoxFactory SecretKey
   deriving (Eq, Ord, Show)

data Box
   = Box BoxFactory PublicKey
   deriving (Eq, Ord, Show)

instance CB.CryptoBox None where
  type PublicKey None = PublicKey
  type SecretKey None = SecretKey
  type BoxFactory   None = BoxFactory
  type Box       None = Box

  newBoxFactory       = return . BoxFactory
  newRandomBoxFactory = return $ BoxFactory (SecretKey "4; // chosen by fair dice roll.")

  newBox f k          = return (Box f k)

  encrypt b message   = return message
  decrypt b cipher    = Just cipher

  publicKey (BoxFactory (SecretKey s))
                      = PublicKey (reverse s)