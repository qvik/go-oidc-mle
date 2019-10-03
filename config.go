package oidc

// Config type will contain all of our configs and secrets
type Config struct {
	ClientId     string
	ClientSecret string
	Endpoint     string
	RedirectUri  string
	MleKey       string
	Scopes       []string
}
