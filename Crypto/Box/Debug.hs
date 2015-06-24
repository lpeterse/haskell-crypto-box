{-# LANGUAGE OverloadedStrings, TypeFamilies #-}
module Crypto.Box.Debug 
  {-# WARNING "This is a dummy implementation and does no encryption at all. Don't use it in production or with confidential data!" #-}
  ( DebugBoxFactory (..)
  , DebugBox        (..)
  , DebugPublicKey  (..)
  , DebugSecretKey  (..)
  ) where

import Data.String
import qualified Crypto.Box as CB

data DebugPublicKey
   = DebugPublicKey String
   deriving (Eq, Ord, Show)

data DebugSecretKey
   = DebugSecretKey String
   deriving (Eq, Ord, Show)

data DebugBoxFactory
   = DebugBoxFactory DebugSecretKey
   deriving (Eq, Ord, Show)

data DebugBox
   = DebugBox DebugBoxFactory DebugPublicKey
   deriving (Eq, Ord, Show)

instance CB.IsBoxFactory DebugBoxFactory where
  type PublicKey  DebugBoxFactory = DebugPublicKey
  type SecretKey  DebugBoxFactory = DebugSecretKey
  type Box        DebugBoxFactory = DebugBox

  newBoxFactory       = return . DebugBoxFactory
  newRandomBoxFactory = return $ DebugBoxFactory (DebugSecretKey "4; // chosen by fair dice roll.")

  newBox f k          = return (DebugBox f k)

  algorithm _         = "None! DANGER! FIXME! DONTUSEINPRODUCTION!"
  publicKey (DebugBoxFactory (DebugSecretKey s)) = DebugPublicKey (reverse s)

instance CB.IsBox DebugBox where
  encrypt b message   = return message
  decrypt b cipher    = return cipher

instance CB.IsKey DebugPublicKey where
  toByteString (DebugPublicKey s) = fromString s
  fromByteString = return . DebugPublicKey . show
  length _ = 0

instance CB.IsKey DebugSecretKey where
  toByteString (DebugSecretKey s) = fromString s
  fromByteString = return . DebugSecretKey . show
  length _ = 0