-- Provision the OAuth-gated user. The first /verify call ClickHouse
-- makes on behalf of this user goes through the ch_jwt_verify backend
-- defined in config.d/http_authentication.xml.
--
-- Grammar wart: the keyword is `http`, NOT `http_authenticator`. The
-- latter fails with SYNTAX_ERROR.
CREATE USER IF NOT EXISTS "alice@example.com"
  IDENTIFIED WITH http SERVER 'ch_jwt_verify' SCHEME 'BASIC';

GRANT SELECT ON system.* TO "alice@example.com";
GRANT SELECT ON default.* TO "alice@example.com";
