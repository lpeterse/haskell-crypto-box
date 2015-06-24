{-# LANGUAGE TypeFamilies #-}
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
-- > import Crypto.Box.None (None)
-- > import Crypto.Saltine.Core.Box (Saltine)
-- > import Data.ByteString as B
-- >
-- > -- Choose an implementation of the `HasBox` functionality.
-- > type Crypto = Saltine -- use `None` for debugging
-- >
-- > main :: IO ()
-- > main = do
-- >   -- Load the secret key once at the beginning of your program. Don't use it elsewhere!
-- >   factory <- newBoxFactory =<< secretKeyFromByteString =<< B.readFile "secretkey"
-- >   -- This is the only point in your program where you define which `HasBox` implemenation to use.
-- >   app (factory :: BoxFactory Crypto)
-- >
-- > -- The remaining application code does not know about a specific implementation and is therefore
-- > -- limited to the methods defined by the `HasBox` interface. This makes it easy
-- > -- to change the implementation if necessary. It also protects against certain programming errors.
-- > 
-- > app :: HasBox crypto => BoxFactory crypto -> IO ()
-- > app factory = do
-- >   print ("My own public key is " ++ show (publicKey factory))
-- >   print ("Enter your friend's public key:")
-- >   friendsPublicKey <- publicKeyFromByteString =<< B.getLine
-- >   box <- newBox factory friendsPublicKey
-- >   cipherText <- encrypt box "Hello world!"
-- >   print ("Send this cipher text to your friend:" ++ show cipherText)
-- >   print "Enter cipher text received from your friend:"
-- >   message <- decrypt box =<< B.getLine
-- >   print ("The message was:" ++ show message)
-----------------------------------------------------------------------------
module Crypto.Box (
  HasBox (..)
  ) where

import Data.ByteString
import Control.Monad.Catch

class HasBox crypto where
  -- | A `PublicKey` may be shared with others. It's not a secret
  --   and does not need to be protected. It is usually derived from
  --   a `SecretKey`.
  type (PublicKey crypto)
  -- | The `SecretKey` is the part that must be kept private.
  --
  -- - If it has a `Show` instance defined it should be a mock
  --   like @SecretKey xxxxxxxxxxxxx@. The risk of unintentionally
  --   exposing it through log files or stack traces is unacceptable.
  type (SecretKey crypto)
  -- | A `BoxFactory` protects your `SecretKey` from being misused by application code.
  --
  -- - Application code that has a `BoxFactory` in scope should not be able to
  --   extract the secret key from it, but it can nonetheless be used for encryption
  --   and decryption of messages by producing `Box`es for specific communication partners.
  -- - `publicKey` may be used to retrieve the `PublicKey` that belongs to
  --   the encapsulated `SecretKey`.
  type (BoxFactory crypto)
  -- | A `Box` contains the state necessary for repeated encryption and decryption
  --   of messages between you and someone else.
  --
  -- - The creation of a `Box` is (depending on the algorithm) a quite expensive
  --   operation. The `Box` should be reused if possible.
  type (Box crypto)

  -- | Create a new `BoxFactory` from a given `SecretKey`.
  --
  -- - Try to do this once near the beginning of your program and drop
  --   the `SecretKey` afterwards.
  newBoxFactory       :: SecretKey crypto -> IO (BoxFactory crypto)

  -- | Create a new `BoxFactory` with a random `SecretKey`.
  --
  -- - The `SecretKey` is lost when the program ends as it cannot be
  --   extracted.
  newRandomBoxFactory :: IO (BoxFactory crypto)

  -- | Create a new `Box` for private communication with someone else identified by `PublicKey`.
  newBox              :: BoxFactory crypto -> PublicKey crypto -> IO (Box crypto)

  -- | Encrypt a message.
  --
  -- - The computation is in `IO` as randomness might be required. The result is therefore non-deterministic.
  encrypt   :: Box crypto -> ByteString -> IO ByteString
  -- | Decrypt and authenticate a message.
  --
  -- - Fails if the message has been tampered with.
  decrypt   :: MonadThrow m => Box crypto -> ByteString -> m ByteString

  -- | Extract __your own__ `PublicKey` from the `BoxFactory`.
  publicKey :: BoxFactory crypto -> PublicKey crypto

  publicKeyToByteString   :: PublicKey crypto -> ByteString
  publicKeyFromByteString :: MonadThrow m => ByteString -> m (PublicKey crypto)

  -- | This is dangerous. Think twice what you're doing!
  secretKeyToByteString   :: SecretKey crypto -> ByteString
  secretKeyFromByteString :: MonadThrow m => ByteString -> m (SecretKey crypto)
