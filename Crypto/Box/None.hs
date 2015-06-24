{-# LANGUAGE OverloadedStrings, TypeFamilies #-}
module Crypto.Box.None (
    None
  , PublicKey (..)
  , SecretKey
  , BoxFactory
  , Box
  ) where

import Data.String
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

instance CB.IsBoxFactory BoxFactory where
  type PublicKey  BoxFactory = PublicKey
  type SecretKey  BoxFactory = SecretKey
  type Box        BoxFactory = Box

  newBoxFactory       = return . BoxFactory
  newRandomBoxFactory = return $ BoxFactory (SecretKey "4; // chosen by fair dice roll.")

  newBox f k          = return (Box f k)

  algorithm _         = "None! DANGER! FIXME! DONTUSEINPRODUCTION!"
  publicKey (BoxFactory (SecretKey s)) = PublicKey (reverse s)

instance CB.IsBox Box where

  encrypt b message   = return message
  decrypt b cipher    = return cipher

instance CB.IsKey PublicKey where
  toByteString (PublicKey s) = fromString s
  fromByteString = return . PublicKey . show
  length _ = 0

instance CB.IsKey SecretKey where
  toByteString (SecretKey s) = fromString s
  fromByteString = return . SecretKey . show
  length _ = 0