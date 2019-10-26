package oidc

// Config represents the configuration parameters needed for initialising
// OIDCClient or OIDClientEncrypted.
//
// ClientId is the client id received from the OIDC provider.
// ClientSecret is the client secret received from the OIDC provider.
// Endpoint is the OIDC provider's service endpoint.
// RedirectUri is the redirect uri the provider will redirect the user after authorization.
// MleKey is the JWK we'll use to encrypt the authorization request. It's not
// needed if MLE is not used. The public must be sent to OIDC provider.
// Scopes is a list of values that specify which access privileges are being requested
// from the access token. Must include openid!
type Config struct {
	ClientId     string
	ClientSecret string
	Endpoint     string
	RedirectUri  string
	MleKey       string
	Scopes       []string
}
