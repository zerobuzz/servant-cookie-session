{-# LANGUAGE ConstraintKinds       #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}

module Servant.Missing
  ( ThrowServantErr(..)
  , MonadServantErr
  , ThrowError500(..)
  , MonadError500
  ) where

import Control.Lens (prism, Prism', (#))

import Control.Monad.Except (MonadError, throwError)
import Data.String.Conversions (cs)
import Servant.Server (ServantErr(..), err500)


class ThrowServantErr err where
    _ServantErr :: Prism' err ServantErr
    throwServantErr :: MonadError err m => ServantErr -> m any
    throwServantErr err = throwError $ _ServantErr # err

type MonadServantErr err m = (MonadError err m, ThrowServantErr err)

instance ThrowServantErr ServantErr where
    _ServantErr = id

class ThrowError500 err where
    error500 :: Prism' err String

    throwError500 :: MonadError err m => String -> m b
    throwError500 err = throwError $ error500 # err

type MonadError500 err m = (MonadError err m, ThrowError500 err)

instance ThrowError500 ServantErr where
    error500 = prism (\msg -> err500 { errBody = cs msg })
                     (\err -> if errHTTPCode err == 500 then Right (cs (errBody err)) else Left err)
