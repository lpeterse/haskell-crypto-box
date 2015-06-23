{-# LANGUAGE TypeFamilies #-}
module Crypto.Box (
  CryptoBox (..)
  ) where

import Control.Monad.IO.Class
import Control.Monad.Catch

import Data.ByteString

class CryptoBox b where
  -- | A `PublicKey` may be shared with others. It's not a secret
  --   and does not need to be protected. It is usually derived from
  --   a `SecretKey`.
  type (PublicKey b)
  -- | The `SecretKey` is the part that must be kept private.
  --
  -- - If it has a `Show` instance defined it should be a mock
  --   like @SecretKey xxxxxxxxxxxxx@. The risk of unintentionally
  --   exposing it through log files or stack traces is unacceptable.
  type (SecretKey b)
  -- | A `Factory` protects your `SecretKey` from being misused by application code.
  --
  -- - Application code that has a `Factory` in scope should not be able to
  --   extract the secret key from it, but it can still use it for encryption
  --   and decryption by producing a `Box` first.
  -- - `publicKey` may be used to retrieve the `PublicKey` that belongs to
  --   the encapsulated `SecretKey`.
  type (Factory b)
  -- | A `Box` contains the state necessary for repeated encryption and decryption
  --   of messages between you and someone else.
  --
  -- - The creation of a `Box` is (depending on the algorithm) a quite expensive
  --   operation. The `Box` should be reused if possible.
  type (Box b)

  -- | This creates a `Factory` from a given `SecretKey`.
  --
  -- - Try to do this once near the beginning of your program and drop
  --   the `SecretKey` afterwards.
  createFactory       :: SecretKey b -> IO (Factory b)

  -- | This creates a `Factory` with a random `SecretKey`.
  --
  -- - The `SecretKey` is lost when the program ends as it cannot be
  --   extracted.
  createRandomFactory :: IO (Factory b)

  -- | Get a `Box` for private communication with someone else identified by `PublicKey`.
  box       :: Factory b -> PublicKey b -> Box b

  -- | Encrypt a message.
  --
  -- - The computation is in `IO` as randomness might be required. The result is therefore non-deterministic.
  encrypt   :: Box b -> ByteString -> IO ByteString
  -- | Decrypt and authenticate a message.
  --
  -- - `Nothing` is returned if the message has been tampered with.
  decrypt   :: Box b -> ByteString -> Maybe ByteString

  -- | Extract __your own__ `PublicKey` from the `Factory`.
  publicKey :: Factory b -> PublicKey b



