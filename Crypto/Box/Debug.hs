{-# LANGUAGE OverloadedStrings, TypeFamilies #-}
module Crypto.Box.Debug 
  {-# WARNING "This is a dummy implementation and does no encryption at all. Don't use it in production or with confidential data!" #-}
  ( DebugKeyHolder  (..)
  , DebugSecretary    (..)
  , DebugPublicKey  (..)
  , DebugSecretKey  (..)
  ) where

import Data.String
import Crypto.Box

data DebugPublicKey
   = DebugPublicKey String
   deriving (Eq, Ord, Show)

data DebugSecretKey
   = DebugSecretKey String
   deriving (Eq, Ord, Show)

data DebugKeyHolder
   = DebugKeyHolder DebugSecretKey
   deriving (Eq, Ord, Show)

data DebugSecretary
   = DebugSecretary DebugKeyHolder DebugPublicKey
   deriving (Eq, Ord, Show)

instance IsKeyHolder DebugKeyHolder where
  type PublicKey  DebugKeyHolder = DebugPublicKey
  type SecretKey  DebugKeyHolder = DebugSecretKey
  type Secretary  DebugKeyHolder = DebugSecretary

  newKeyHolder        = return . DebugKeyHolder
  newRandomKeyHolder  = return $ DebugKeyHolder (DebugSecretKey "4; // chosen by fair dice roll.")

  newSecretary f k    = return (DebugSecretary f k)

  primitive _         = "Debug! DANGER! FIXME! DONTUSEINPRODUCTION!"
  publicKey (DebugKeyHolder (DebugSecretKey s)) = DebugPublicKey (reverse s)

instance IsSecretary DebugSecretary where
  encrypt b message   = return message
  decrypt b cipher    = return cipher

instance IsKey DebugPublicKey where
  toByteString (DebugPublicKey s) = fromString s
  fromByteString = return . DebugPublicKey . show
  length _ = 0

instance IsKey DebugSecretKey where
  toByteString (DebugSecretKey s) = fromString s
  fromByteString = return . DebugSecretKey . show
  length _ = 0