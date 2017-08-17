{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE KindSignatures        #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TupleSections         #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}

module Servant.Cookie.Session
    ( serveAction
    , enterAction

    -- * types
    , SessionStorage
    , SessionKey
    , Lockable

    -- * necessary modules
    , module Web.Cookie
    , module Crypto.Random
    , module Servant.Cookie.Session.CSRF
    , module Servant.Cookie.Session.Types
    , module Servant.Cookie.Session.Error
    )
where

import Control.Concurrent.MVar (MVar, newEmptyMVar, takeMVar, putMVar)
import Control.Lens (use)
import Control.Monad.Except.Missing (finally)
import Control.Monad.IO.Class (MonadIO(..))
import Control.Monad.State.Class (MonadState(..))
import Control.Monad.Trans.Except (ExceptT)
import Control.Monad (when)
import Crypto.Random (MonadRandom(..))
import Data.Char (ord)
import Data.Maybe (fromMaybe, isJust)
import Data.Proxy (Proxy(Proxy))
import Data.String.Conversions
import Network.Wai (Middleware, Application, vault)
import Network.Wai.Session.Map (mapStore_)
import Network.Wai.Session (SessionStore, Session, withSession)
import Servant
import Servant.Server.Internal (route, passToServer, responseServantErr)
import Servant.Utils.Enter (Enter, enter)
import Web.Cookie

import qualified Data.ByteString as SBS
import qualified Data.Vault.Lazy as V

import Servant.Cookie.Session.CSRF
import Servant.Cookie.Session.Error
import Servant.Cookie.Session.Types


-- * servant integration

-- | @SessionStorage m k v@ represents a session storage with keys of type @k@,
-- values of type @fsd@, and operating under the monad @m@.
-- The underlying implementation uses the 'wai-session' package, and any
-- backend compatible with that package should work here too.
data SessionStorage (m :: * -> *) (k :: *) (fsd :: *)

-- | 'HasServer' instance for 'SessionStorage'.
instance (HasServer sublayout context) => HasServer (SessionStorage n k fsd :> sublayout) context where
  type ServerT (SessionStorage n k fsd :> sublayout) m
    = (V.Key (Session n k (Lockable fsd)) -> Maybe (Session n k (Lockable fsd))) -> ServerT sublayout m
  route Proxy context subserver =
    route (Proxy :: Proxy sublayout) context (passToServer subserver go)
    where
      go request key = V.lookup key $ vault request

type SessionKey fsd = V.Key (Session IO () (Lockable fsd))

-- | The underlying wai-session package expects concurrent requests to operate on the same @Session
-- m k v@ value: two ajax requests in the same session can be processed concurrently and
-- alternatingly lookup or insert session values. This is arguably ok, since the interface does not
-- promise any atomicity between lookup and insert, and it is certainly efficient.
--
-- However, this package assumes a lock (not unlike 'takeMVar') on the session value throughout the
-- run of one handler action, and this is not guaranteed.  When the assumption breaks, there will be
-- a race between the concurrent threads about who gets to overwrite whose updates.
--
-- In order to avoid the race condition, we carry around the 'MVar' hidden inside this module so we
-- can take and put at the appropriate places before and after running the servant handler.  The
-- servant-cookie-session user does not need to worry about this.
type Lockable fsd = (fsd, MVar ())


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

-- | (the key is the same over the lifetime of the server process, but it needs to be applied to a
-- fresh state each time a new request brings a new cookie value.)
sessionMiddleware :: Proxy fsd -> SetCookie -> IO (Middleware, SessionStore IO () (Lockable fsd), SessionKey fsd)
sessionMiddleware Proxy setCookie = do
    smap :: SessionStore IO () (Lockable fsd) <- mapStore_
    key  :: SessionKey fsd <- V.newKey
    return (withSession smap (cookieName setCookie) setCookie key, smap, key)


-- * frontend action monad

serveAction :: forall m e fsd csrf api.
        ( HasServer api '[]
        , Enter (ServerT api m) (m :~> ExceptT ServantErr IO) (Server api)
        , MonadRandom m, MonadError500 e m, MonadSessionCsrfToken fsd m
        , MonadViewCsrfSecret csrf m, MonadSessionToken fsd m
        , MonadIO m
        )
     => Proxy api
     -> Proxy fsd
     -> SetCookie
     -> IO :~> m
     -> m :~> ExceptT ServantErr IO
     -> ServerT api m
     -> Maybe Application
     -> IO (Application, SessionStore IO () (Lockable fsd))
serveAction _ sProxy setCookie ioNat nat fServer mFallback =
    app <$> sessionMiddleware sProxy setCookie
  where
    app :: (Middleware, SessionStore IO () (Lockable fsd), SessionKey fsd)
        -> (Application, SessionStore IO () (Lockable fsd))
    app (mw, smap, key) = ( mw $ serve (Proxy :: Proxy ((SessionStorage IO () fsd :> api) :<|> Raw))
                                       (server' key :<|> fallback)
                          , smap )

    error404 :: Application
    error404 = serve (Proxy :: Proxy Raw) (\_ respond -> respond $ responseServantErr err404)

    fallback = fromMaybe error404 mFallback

    server' :: SessionKey fsd -> (SessionKey fsd -> Maybe (Session IO () (Lockable fsd))) -> Server api
    server' key smap = enter nt fServer
      where
        nt :: m :~> ExceptT ServantErr IO
        nt = enterAction (smap key) ioNat nat

enterAction
    :: forall m e fsd csrf.
       ( MonadRandom m, MonadError500 e m, MonadSessionCsrfToken fsd m
       , MonadViewCsrfSecret csrf m, MonadSessionToken fsd m
       , MonadIO m
       )
    => Maybe (Session IO () (Lockable fsd))
    -> IO :~> m
    -> m :~> ExceptT ServantErr IO
    -> m :~> ExceptT ServantErr IO
enterAction mfsd ioNat nat = Nat $ \fServer -> unNat nat $ do
    case mfsd of
        Nothing ->
            -- FIXME: this case should not be code 500, as it can (probably) be provoked by
            -- the client.
            throwError500 "Could not read cookie."
        Just (lkup, ins) -> do
            lock :: MVar () <- liftIO $ lkup () >>= maybe
              newEmptyMVar
              (\(_, lock) -> takeMVar lock >> pure lock)

            (prepare (fmap fst <$> lkup ()) >> fServer)
              `finally` cleanup (ins ()) lock
  where
    prepare :: IO (Maybe fsd) -> m ()
    prepare lkup = do
      cookieToSession lkup
      maybeSessionToken <- use getSessionToken
      -- refresh the CSRF token if there is a session token
      when (isJust maybeSessionToken) refreshCsrfToken

    cleanup :: (Lockable fsd -> IO ()) -> MVar () -> m ()
    cleanup ins lock = do
      clearCsrfToken  -- could be replaced by 'refreshCsrfToken'
      cookieFromSession (ins . (, lock))
      liftIO $ putMVar lock ()

    -- | Write 'FrontendSessionData' from the 'SSession' state to 'MonadFAction' state.  If there
    -- is no state, do nothing.
    cookieToSession :: IO (Maybe fsd) -> m ()
    cookieToSession r = unNat ioNat r >>= mapM_ put

    -- | Read 'FrontendSessionData' from 'MonadFAction' and write back into 'SSession' state.
    cookieFromSession :: (fsd -> IO ()) -> m ()
    cookieFromSession w = get >>= unNat ioNat . w
