{-# LANGUAGE TypeFamilies, FlexibleContexts #-}
-----------------------------------------------------------------------------
-- |
-- Module      :  Crypto.Box
-- Copyright   :  (c) Lars Petersen 2015
-- License     :  MIT
--
-- Maintainer  :  info@lars-petersen.net
-- Stability   :  experimental
-- Portability :  portable
--
-- > {-# LANGUAGE OverloadedStrings #-}
-- > module Main where
-- >
-- > import Crypto.Box
-- > import Crypto.Box.Debug
-- > import Data.ByteString as B
-- >
-- > -- Choose an implementation (Saltine or similar).
-- > -- Attention: `DebugBoxFactory` does no encryption at all.
-- > type Factory = DebugBoxFactory
-- >
-- > main :: IO ()
-- > main = do
-- >   -- Load the secret key once at the beginning of your program. Don't use it elsewhere!
-- >   factory <- newBoxFactory =<< fromByteString =<< B.readFile "secretkey"
-- >   -- This is the only point in your program where you define which implemenation to use.
-- >   app (factory :: Factory)
-- >
-- > -- The remaining application code does not know about a specific implementation and is therefore
-- > -- limited to the methods defined by the `IsBoxFactory` and `IsBox` interfaces. This makes it easy
-- > -- to change the implementation if necessary. It also protects against certain programming errors.
-- >
-- > app :: IsBoxFactory f => f -> IO ()
-- > app factory = do
-- >   print ("Algorithm used is" ++ show (algorithm factory))
-- >   print ("My own public key is " ++ show (toByteString $ publicKey factory))
-- >   print ("Enter your friend's public key:")
-- >   friendsPublicKey <- fromByteString =<< B.getLine
-- >   box <- newBox factory friendsPublicKey
-- >   cipherText <- encrypt box "Hello world!"
-- >   print ("Send this cipher text to your friend:" ++ show cipherText)
-- >   print ("Enter cipher text received from your friend:")
-- >   message <- decrypt box =<< B.getLine
-- >   print ("The message was:" ++ show message)
-----------------------------------------------------------------------------
module Crypto.Box (
    IsBoxFactory (..)
  , IsBox (..)
  , IsKey (..)
  ) where

import Data.ByteString
import Control.Monad.Catch
import Control.Monad.IO.Class

class (IsBox (Box f), IsKey (PublicKey f), IsKey (SecretKey f)) => IsBoxFactory f where
  -- | A `PublicKey` may be shared with others. It's not a secret
  --   and does not need to be protected. It is usually derived from
  --   a `SecretKey`.
  type (PublicKey f)
  -- | The `SecretKey` is the part that must be kept private.
  --
  -- - If it has a `Show` instance defined it should be a mock
  --   like @SecretKey xxxxxxxxxxxxx@. The risk of unintentionally
  --   exposing it through log files or stack traces is unacceptable.
  type (SecretKey f)
  -- | A `Box` contains the state necessary for repeated encryption and decryption
  --   of messages between you and someone else.
  --
  -- - The creation of a `Box` is (depending on the algorithm) a quite expensive
  --   operation. The `Box` should be reused if possible.
  type (Box f)
  -- | Create a new `BoxFactory` from a given `SecretKey`.
  --
  -- - Try to do this once near the beginning of your program and drop
  --   the `SecretKey` afterwards.
  newBoxFactory       :: MonadIO m => SecretKey f -> m f
  -- | Create a new `BoxFactory` with a random `SecretKey`.
  --
  -- - The `SecretKey` is lost when the program ends as it cannot be
  --   extracted.
  newRandomBoxFactory :: MonadIO m => m f
  -- | Create a new `Box` for private communication with someone else identified by `PublicKey`.
  newBox              :: MonadIO m => f -> PublicKey f -> m (Box f)

  -- | A short description of the algorithm suite, i.e. @curve25519xsalsa20poly1305@.
  algorithm           :: f -> ByteString

  -- | Extract __your own__ `PublicKey` from the `BoxFactory`.
  publicKey           :: f -> PublicKey f

class IsBox b where
  -- | Encrypt a message.
  --
  -- - The computation is in `IO` as randomness might be required. The result is therefore non-deterministic.
  encrypt   :: MonadIO m => b -> ByteString -> m ByteString
  -- | Decrypt and authenticate a message.
  --
  -- - Fails if the message has been tampered with.
  decrypt   :: MonadThrow m => b -> ByteString -> m ByteString

class IsKey k where
  toByteString   :: k -> ByteString
  fromByteString ::MonadThrow m => ByteString -> m k
  length         :: k -> Int
