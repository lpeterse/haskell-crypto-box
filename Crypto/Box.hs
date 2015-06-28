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
-- > main :: IO ()
-- > main = do
-- >   -- Load the secret key once at the beginning of your program. Don't use it elsewhere!
-- >   keyHolder <- newKeyHolder =<< fromByteString =<< B.readFile "secretkey"
-- >   -- This is the only point in your program where you define which implemenation to use.
-- >   app (keyHolder :: DebugKeyHolder)
-- > 
-- > -- The remaining application code does not know about a specific implementation and is therefore
-- > -- limited to the methods defined by the `IsKeyHolder` and `IsSecretary` interfaces. This makes it easy
-- > -- to change the implementation if necessary. It also protects against certain programming errors.
-- > 
-- > app :: IsKeyHolder k => k -> IO ()
-- > app keyHolder = do
-- >   print ("Algorithm used is " ++ show (primitive keyHolder))
-- >   print ("My own public key is " ++ show (toByteString $ publicKey keyHolder))
-- >   print ("Enter your friend's public key:")
-- >   friendsPublicKey <- fromByteString =<< B.getLine
-- >   secretary <- newSecretary keyHolder friendsPublicKey
-- >   cipherText <- encrypt secretary "Hello world!"
-- >   print ("Send this cipher text to your friend: " ++ show cipherText)
-- >   print ("Enter cipher text received from your friend: ")
-- >   message <- decrypt secretary =<< B.getLine
-- >   print ("The message was: " ++ show message)
-----------------------------------------------------------------------------
module Crypto.Box (
    IsKeyHolder (..)
  , IsSecretary (..)
  , IsKey (..)
  ) where

import Data.ByteString
import Control.Monad.Catch
import Control.Monad.IO.Class

class (IsSecretary (Secretary k), IsKey (PublicKey k), IsKey (SecretKey k)) => IsKeyHolder k where
  -- | A `PublicKey` may be shared with others. It's not a secret
  --   and does not need to be protected. It is usually derived from
  --   a `SecretKey`.
  type (PublicKey k)
  -- | The `SecretKey` is the part that must be kept private.
  --
  -- - If it has a `Show` instance defined it should be a mock
  --   like @SecretKey xxxxxxxxxxxxx@. The risk of unintentionally
  --   exposing it through log files or stack traces is unacceptable.
  type (SecretKey k)
  -- | A `Secretary` contains the state necessary for repeated encryption and decryption
  --   of messages between you and someone else.
  --
  -- - The creation of a `Secretary` is (depending on the algorithm) a quite expensive
  --   operation. The `Secretary` should be reused if possible.
  type (Secretary k)
  -- | Create a new `KeyHolder` from a given `SecretKey`.
  --
  -- - Try to do this once near the beginning of your program and drop
  --   the `SecretKey` afterwards.
  newKeyHolder        :: MonadIO m => SecretKey k -> m k
  -- | Create a new `KeyHolder` with a random `SecretKey`.
  --
  -- - The `SecretKey` is lost when the program ends as it cannot be
  --   extracted.
  newRandomKeyHolder  :: MonadIO m => m k
  -- | Create a new `Secretary` for processing the private communication with someone else identified by `PublicKey`.
  newSecretary        :: MonadIO m => k -> PublicKey k -> m (Secretary k)

  -- | A short description of the algorithm suite, i.e. @curve25519xsalsa20poly1305@.
  primitive           :: k -> ByteString

  -- | Get __your own__ `PublicKey` from the `KeyHolder`.
  publicKey           :: k -> PublicKey k

class IsSecretary s where
  -- | Encrypt a message.
  --
  -- - The computation is in `IO` as randomness might be required. The result is therefore non-deterministic.
  encrypt   :: MonadIO m => s -> ByteString -> m ByteString
  -- | Decrypt and authenticate a message.
  --
  -- - Fails if the message has been tampered with.
  decrypt   :: MonadThrow m => s -> ByteString -> m ByteString

class IsKey k where
  toByteString   :: k -> ByteString
  fromByteString :: MonadThrow m => ByteString -> m k
  length         :: k -> Int
