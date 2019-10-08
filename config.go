package oidc

// Config represents the configuration parameters needed for initialising OIDCClient or OIDClientEncrypted.
type Config struct {
	ClientId     string
	ClientSecret string
	Endpoint     string
	RedirectUri  string
	MleKey       string
	Scopes       []string
}
