{-# LANGUAGE TypeFamilies #-}
module Crypto.Box (
  CryptoBox (..)
  ) where

import Data.ByteString
import Control.Monad.Catch

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
  -- | A `BoxFactory` protects your `SecretKey` from being misused by application code.
  --
  -- - Application code that has a `BoxFactory` in scope should not be able to
  --   extract the secret key from it, but it can still use it for encryption
  --   and decryption by producing a `Box` first.
  -- - `publicKey` may be used to retrieve the `PublicKey` that belongs to
  --   the encapsulated `SecretKey`.
  type (BoxFactory b)
  -- | A `Box` contains the state necessary for repeated encryption and decryption
  --   of messages between you and someone else.
  --
  -- - The creation of a `Box` is (depending on the algorithm) a quite expensive
  --   operation. The `Box` should be reused if possible.
  type (Box b)

  -- | Create a new `BoxFactory` from a given `SecretKey`.
  --
  -- - Try to do this once near the beginning of your program and drop
  --   the `SecretKey` afterwards.
  newBoxFactory       :: SecretKey b -> IO (BoxFactory b)

  -- | Create a new `BoxFactory` with a random `SecretKey`.
  --
  -- - The `SecretKey` is lost when the program ends as it cannot be
  --   extracted.
  newRandomBoxFactory :: IO (BoxFactory b)

  -- | Create a new `Box` for private communication with someone else identified by `PublicKey`.
  newBox              :: BoxFactory b -> PublicKey b -> IO (Box b)

  -- | Encrypt a message.
  --
  -- - The computation is in `IO` as randomness might be required. The result is therefore non-deterministic.
  encrypt   :: Box b -> ByteString -> IO ByteString
  -- | Decrypt and authenticate a message.
  --
  -- - Fails if the message has been tampered with.
  decrypt   :: MonadThrow m => Box b -> ByteString -> m ByteString

  -- | Extract __your own__ `PublicKey` from the `BoxFactory`.
  publicKey :: BoxFactory b -> PublicKey b

  publicKeyToByteString   :: PublicKey b -> ByteString
  publicKeyFromByteString :: MonadThrow m => ByteString -> m (PublicKey b)

  -- | This is dangerous. Think twice what you're doing!
  secretKeyToByteString   :: SecretKey b -> ByteString
  secretKeyFromByteString :: MonadThrow m => ByteString -> m (SecretKey b)
