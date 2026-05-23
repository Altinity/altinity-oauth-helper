# Superset config for the docker-compose example.
#
# Adapts the production Auth0 overlay at
#   examples/superset-otel/superset-values.yaml
# to a local Dex IdP, with a generic OIDC userinfo fetch in place of
# Auth0's Bearer-token-against-/userinfo specifics. Three deliberate
# differences:
#   1. OAUTH_PROVIDERS uses split browser/backend URLs (Dex's issuer is
#      browser-facing but containers reach Dex via the docker-DNS name).
#   2. _userinfo() is a generic authlib remote.get("userinfo"); no
#      Auth0-specific claim mapping is needed because Dex emits OIDC
#      standard claims.
#   3. The metadata DB connection points at the shared postgres service
#      (which the chart manages in the helm example).
import logging
import os
import threading
import time

from flask import g, session
from flask_appbuilder.security.manager import AUTH_OAUTH
from superset.security import SupersetSecurityManager


SECRET_KEY = os.environ["SUPERSET_SECRET_KEY"]
SQLALCHEMY_DATABASE_URI = os.environ["SQLALCHEMY_DATABASE_URI"]

_jwt_log = logging.getLogger("superset.jwt_overlay")

# OAuth provider — Dex.
AUTH_TYPE = AUTH_OAUTH
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = os.environ.get("AUTH_USER_REGISTRATION_ROLE", "Admin")
AUTH_ROLES_SYNC_AT_LOGIN = False

# Browser-facing Dex URL (used in HTTP 302 redirects sent to the user).
_DEX_PUBLIC = os.environ.get("DEX_PUBLIC_URL", "http://localhost:5556/dex")
# Container-facing Dex URL (used by Superset's backend for token exchange
# + userinfo). Inside the docker network `dex` resolves; on the host it
# would not.
_DEX_INTERNAL = os.environ.get("DEX_INTERNAL_URL", "http://dex:5556/dex")

OAUTH_PROVIDERS = [
    {
        "name": "dex",
        "icon": "fa-key",
        "token_key": "access_token",
        "remote_app": {
            "client_id": os.environ["DEX_CLIENT_ID"],
            "client_secret": os.environ["DEX_CLIENT_SECRET"],
            "api_base_url": f"{_DEX_INTERNAL}/",
            "access_token_url": f"{_DEX_INTERNAL}/token",
            "authorize_url": f"{_DEX_PUBLIC}/auth",
            "userinfo_endpoint": f"{_DEX_INTERNAL}/userinfo",
            # Pin jwks_uri to the container-resolvable name. Without this,
            # authlib reads jwks_uri from
            # `.well-known/openid-configuration` — Dex serves it under its
            # browser-facing issuer URL (`http://localhost:5556/dex/keys`)
            # which inside the Superset container resolves to Superset
            # itself, not Dex. So we bypass the discovery doc entirely.
            "jwks_uri": f"{_DEX_INTERNAL}/keys",
            "client_kwargs": {"scope": "openid profile email"},
        },
    }
]

# ---- JWT capture / DB connection mutator -------------------------------
# Per-user JWT cache shared between request and worker threads. Demo-grade
# only (single replica, no eviction). See examples/superset-otel for the
# fuller rationale.
SESSION_TOKEN_KEY = "clickhouse_jwt"
SESSION_TOKEN_EXP_KEY = "clickhouse_jwt_exp"

_jwt_store_lock = threading.Lock()
_jwt_store: dict = {}


def _store_user_jwt(user_id, token, exp):
    with _jwt_store_lock:
        _jwt_store[user_id] = (token, exp)


def _load_user_jwt(user_id):
    with _jwt_store_lock:
        return _jwt_store.get(user_id)


class JWTSecurityManager(SupersetSecurityManager):
    def oauth_user_info(self, provider, response=None):
        if provider != "dex":
            return super().oauth_user_info(provider, response) or {}
        info = self._dex_userinfo()

        if response and isinstance(response, dict):
            access_token = response.get("access_token")
            if access_token:
                session[SESSION_TOKEN_KEY] = access_token
                expires_at = response.get("expires_at")
                if not expires_at and (expires_in := response.get("expires_in")):
                    expires_at = int(time.time()) + int(expires_in)
                if expires_at:
                    session[SESSION_TOKEN_EXP_KEY] = int(expires_at)
                fab_user = self.find_user(email=info.get("email", ""))
                if fab_user and getattr(fab_user, "id", None):
                    _store_user_jwt(fab_user.id, access_token, expires_at)
                _jwt_log.info(
                    "captured OAuth access_token provider=%s email=%s len=%d uid=%s",
                    provider, info.get("email"), len(access_token),
                    getattr(fab_user, "id", None) if fab_user else None,
                )
            else:
                _jwt_log.warning(
                    "OAuth response from provider=%s had no access_token", provider
                )
        return info

    def _dex_userinfo(self):
        # authlib's remote.get() automatically attaches the freshly minted
        # access_token from the in-progress OAuth session as
        # `Authorization: Bearer …`, so we just request /userinfo and read
        # the OIDC-standard claims back.
        remote = self.appbuilder.sm.oauth_remotes["dex"]
        try:
            me = remote.get("userinfo").json()
        except Exception as exc:
            _jwt_log.exception("dex /userinfo fetch failed: %s", exc)
            return {}
        return {
            "username": me.get("email") or me.get("sub"),
            "email": me.get("email", ""),
            "first_name": me.get("given_name", "") or me.get("name", ""),
            "last_name": me.get("family_name", ""),
            "name": me.get("name", ""),
        }


CUSTOM_SECURITY_MANAGER = JWTSecurityManager

_CLICKHOUSE_ENGINES = {"clickhousedb", "clickhouse"}


def DB_CONNECTION_MUTATOR(uri, params, username, security_manager, source):
    backend = (uri.get_backend_name() or "").lower()
    if backend not in _CLICKHOUSE_ENGINES:
        return uri, params

    user = getattr(g, "user", None)
    user_email = (getattr(user, "email", None) or username or "").strip().lower()
    user_id = getattr(user, "id", None) if user is not None else None

    jwt = None
    try:
        jwt = session.get(SESSION_TOKEN_KEY)
    except RuntimeError:
        pass
    if not jwt and user_id is not None:
        entry = _load_user_jwt(user_id)
        if entry:
            jwt, _ = entry
    if not jwt and user_email:
        try:
            fab_user = security_manager.find_user(email=user_email)
            if fab_user and getattr(fab_user, "id", None):
                entry = _load_user_jwt(fab_user.id)
                if entry:
                    jwt, _ = entry
        except Exception:
            pass

    if not jwt or not user_email:
        _jwt_log.info(
            "MUTATOR skip backend=%s reason=%s user_email=%s",
            backend, "no_jwt" if not jwt else "no_email", user_email,
        )
        return uri, params

    new_uri = uri.set(username=user_email, password=jwt)
    ca = params.setdefault("connect_args", {})
    ca["username"] = user_email
    ca["password"] = jwt
    _jwt_log.info(
        "MUTATOR rewrote backend=%s email=%s jwt_len=%d source=%s",
        backend, user_email, len(jwt), source,
    )
    return new_uri, params


# ---- L7 plumbing -------------------------------------------------------
# No edge-proxy in the docker-compose layout; the browser hits Superset
# directly over HTTP. PREFERRED_URL_SCHEME stays "http" so authlib emits
# matching redirect_uris on the wire.
PREFERRED_URL_SCHEME = "http"

# Demo runs without redis. Same NullCache/SimpleCache setup as the helm
# overlay (see examples/superset-otel).
from cachelib.simple import SimpleCache  # noqa: E402
CACHE_CONFIG = {"CACHE_TYPE": "NullCache"}
DATA_CACHE_CONFIG = CACHE_CONFIG
FILTER_STATE_CACHE_CONFIG = CACHE_CONFIG
EXPLORE_FORM_DATA_CACHE_CONFIG = CACHE_CONFIG
RESULTS_BACKEND = SimpleCache(default_timeout=300)
SQLLAB_BACKEND_PERSISTENCE = False
SQLLAB_ASYNC_TIME_LIMIT_SEC = 60

FEATURE_FLAGS = {
    "DASHBOARD_NATIVE_FILTERS": True,
    "DASHBOARD_CROSS_FILTERS": True,
    "ENABLE_TEMPLATE_PROCESSING": True,
}
