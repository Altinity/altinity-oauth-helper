module github.com/altinity/altinity-oauth-helper

go 1.26

require (
	github.com/go-asn1-ber/asn1-ber v1.5.8
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/go-ldap/ldap/v3 v3.4.14
	github.com/rs/zerolog v1.35.1
	github.com/stretchr/testify v1.12.1
	github.com/urfave/cli/v3 v3.10.1
	github.com/vjeantet/goldap v0.0.0-20260720153039-a51461838017
	github.com/vjeantet/ldapserver v1.0.2-0.20260725103726-663e6b9910fb
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/modelcontextprotocol/go-sdk v1.6.1 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
)

require (
	github.com/altinity/go-mcp-oauth-sdk v0.2.0
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// Local fork carrying two fixes upstream lacks as of the pinned version:
// a BER INTEGER sign-disambiguation bug that corrupts MessageID
// correlation past 127, and a missing ModifyDNResponse.SetResultCode
// needed for fail-closed ModifyDN handling. See third_party/goldap/PATCHES.md.
replace github.com/vjeantet/goldap => ./third_party/goldap
