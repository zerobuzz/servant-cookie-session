{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE KindSignatures        #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}

module Servant.Cookie.Session
    ( serveAction
    , enterAction

    -- * types
    , SessionStorage

    -- * necessary modules
    , module Web.Cookie
    , module Crypto.Random
    , module Servant.Cookie.Session.CSRF
    , module Servant.Cookie.Session.Types
    , module Servant.Cookie.Session.Error
    )
where

import Control.Lens (use)
import Control.Monad (when)
import Control.Monad.Except.Missing (finally)
import Control.Monad.State.Class (MonadState(..))
import Control.Monad.Trans.Except (ExceptT)
import Crypto.Random (MonadRandom(..))
import Data.Char (ord)
import Data.Maybe (fromMaybe, isJust)
import Data.Proxy (Proxy(Proxy))
import Data.String.Conversions
import Network.Wai (Middleware, Application, vault)
import qualified Network.Wai.Session as Wai (SessionStore, Session, withSession)
import Servant
import Servant.Server.Internal (route, passToServer, responseServantErr)
import Servant.Utils.Enter (Enter, enter)
import Web.Cookie

import qualified Data.ByteString as SBS
import qualified Data.Vault.Lazy as Vault
import qualified Network.Wai.Session.Map as SessionMap

import Servant.Cookie.Session.CSRF
import Servant.Cookie.Session.Error
import Servant.Cookie.Session.Types


-- * servant integration

-- | @SessionStorage m k v@ represents a session storage with keys of type @k@,
-- values of type @v@, and operating under the monad @m@.
-- The underlying implementation uses the 'wai-session' package, and any
-- backend compatible with that package should work here too.
data SessionStorage (m :: * -> *) (v :: *)

data SessionKey = SessionKey

-- | 'HasServer' instance for 'SessionStorage'.
instance (HasServer sublayout context, Vault.Key v ~ SessionKey) => HasServer (SessionStorage n v :> sublayout) context where
  type ServerT (SessionStorage n v :> sublayout) m
    = Maybe (Wai.Session n SessionKey v) -> ServerT sublayout m
  route Proxy context subserver =
    route (Proxy :: Proxy sublayout) context (passToServer subserver go)
    where
      go request = Vault.lookup SessionKey $ vault request


{-
type SimpleSessionStore m fsd = Maybe SBS -> IO ((m (Maybe fsd), fsd -> m SessionKey), IO SBS)

mkSimpleSessionStore :: forall fsd. SessionStore fsd -> SimpleSessionStore IO fsd
mkSimpleSessionStore store = fmap (\((getst :: SessionKey -> IO (Maybe fsd), setst :: SessionKey -> _), _ :: _) -> _) . store
-}



-- * middleware

cookieName :: SetCookie -> SBS
cookieName setCookie =
    if cookieNameValid n
        then n
        else error $ "Servant.Cookie.Session: bad cookie name: " ++ show n
  where
    n = setCookieName setCookie

cookieNameValid :: SBS -> Bool
cookieNameValid = SBS.all (`elem` (fromIntegral . ord <$> '_':['a'..'z']))

sessionMiddleware :: Proxy fsd -> SetCookie -> IO Middleware
sessionMiddleware Proxy setCookie = do
    smap :: Wai.SessionStore IO SessionKey fsd <- SessionMap.mapStore_
    return (Wai.withSession smap (cookieName setCookie) setCookie SessionKey)


-- * frontend action monad

serveAction :: forall api m s e v.
        ( HasServer api '[]
        , Enter (ServerT api m) (m :~> ExceptT ServantErr IO) (Server api)
        , MonadRandom m, MonadError500 e m, MonadSessionCsrfToken s m
        , MonadViewCsrfSecret v m, MonadSessionToken s m
        )
     => Proxy api
     -> Proxy s
     -> SetCookie
     -> IO :~> m
     -> m :~> ExceptT ServantErr IO
     -> ServerT api m
     -> Maybe Application
     -> IO Application
serveAction _ sProxy setCookie ioNat nat fServer mFallback =
    app <$> sessionMiddleware sProxy setCookie
  where
    app :: Middleware -> Application
    app mw = mw $ serve (Proxy :: Proxy ((SessionStorage IO s :> api) :<|> Raw)) (server' :<|> fallback)

    error404 :: Application
    error404 = serve (Proxy :: Proxy Raw) (\_ respond -> respond $ responseServantErr err404)

    fallback = fromMaybe error404 mFallback

    server' :: (SessionKey -> Maybe (Wai.Session IO SessionKey s)) -> Server api
    server' smap = enter nt fServer
      where
        nt :: m :~> ExceptT ServantErr IO
        nt = enterAction smap ioNat nat

enterAction
    :: ( MonadRandom m, MonadError500 e m, MonadSessionCsrfToken s m
       , MonadViewCsrfSecret v m, MonadSessionToken s m)
    => (SessionKey -> Maybe (Wai.Session IO SessionKey s))
    -> IO :~> m
    -> m :~> ExceptT ServantErr IO
    -> m :~> ExceptT ServantErr IO
enterAction smap ioNat nat = Nat $ \fServer -> unNat nat $ do
    case smap SessionKey of
        Nothing ->
            -- FIXME: this case should not be code 500, as it can (probably) be provoked by
            -- the client.
            throwError500 "Could not read cookie."
        Just (lkup, ins) -> do
            cookieToSession ioNat (lkup SessionKey)
            maybeSessionToken <- use getSessionToken

            -- refresh the CSRF token if there is a session token
            when (isJust maybeSessionToken) refreshCsrfToken

            fServer `finally` (do
                clearCsrfToken  -- could be replaced by 'refreshCsrfToken'
                cookieFromSession ioNat (ins SessionKey))

  where
    -- | Write 'FrontendSessionData' from the 'SSession' state to 'MonadFAction' state.  If there
    -- is no state, do nothing.
    cookieToSession :: MonadState s m => IO :~> m -> IO (Maybe s) -> m ()
    cookieToSession ioNat r = unNat ioNat r >>= mapM_ put

    -- | Read 'FrontendSessionData' from 'MonadFAction' and write back into 'SSession' state.
    cookieFromSession :: MonadState s m => IO :~> m -> (s -> IO ()) -> m ()
    cookieFromSession ioNat w = get >>= unNat ioNat . w
