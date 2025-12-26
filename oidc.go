// Package oidc provides OpenID Connect wrapper that implements message level encryption using the optional
// encrypted request object.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"golang.org/x/oauth2"
)

// OIDCInterface defines the functions that the clients must implement.
type OIDCInterface interface {
	Exchange(string, map[string]string) (*Tokens, error)
	ExchangeWithNonce(string, string, map[string]string) (*Tokens, error)
	AuthRequestURL(string, map[string]interface{}) (string, error)
	Verify(string) (*oidc.IDToken, error)
	UserInfo(oauth2.TokenSource, interface{}) error
	HandleCallback(string, string, url.Values, interface{}) error
}

// Must is a convenience function to make sure that the OIDC client is
// successfully initialised. If the client initialization fails the function
// panics.
func Must(client OIDCInterface, err error) OIDCInterface {
	if err != nil {
		panic(err)
	}

	return client
}

// NewClient initializes and returns OIDClient that can be used to implement
// OIDC authorization code flow. Discovery is used to read the provider's oidc
// configuration.
func NewClient(ctx context.Context, config *Config) (*OIDCClient, error) {
	config.Scopes = addOpenIdToScope(config.Scopes)
	oidcProvider, err := oidc.NewProvider(ctx, config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize client: %w", err)
	}

	oidcConfig := &oidc.Config{
		ClientID: config.ClientId,
	}

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientId,
		ClientSecret: config.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  config.RedirectUri,
		Scopes:       config.Scopes,
	}

	return &OIDCClient{
		oauth2Config: &oauth2Config,
		oidcConfig:   oidcConfig,
		provider:     oidcProvider,
		config:       config,
		ctx:          ctx,
	}, nil
}

// NewClientMLE initialises and returns OIDClientEncrypted which can be used
// to implement OIDC authorization code flow with message level encryption.
// Discovery is used to read the provider's oidc configuration.
func NewClientMLE(ctx context.Context, config *Config) (*OIDCClientEncrypted, error) {
	config.Scopes = addOpenIdToScope(config.Scopes)
	oidcProvider, err := oidc.NewProvider(ctx, config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize client: %w", err)
	}

	var endpoints providerEndpoints
	err = oidcProvider.Claims(&endpoints)
	if err != nil {
		return nil, err
	}

	remoteKeySet, err := providerRemoteKeys(ctx, endpoints.JwksURL)
	if err != nil {
		return nil, err
	}

	oidcConfig := &oidc.Config{
		ClientID: config.ClientId,
	}
	oauth2Config := oauth2.Config{
		ClientID:     config.ClientId,
		ClientSecret: config.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  config.RedirectUri,
		Scopes:       config.Scopes,
	}

	var localKey jose.JSONWebKey
	err = json.Unmarshal([]byte(config.LocalJWK), &localKey)
	if err != nil {
		return nil, err
	}

	return &OIDCClientEncrypted{
		oauth2Config:  &oauth2Config,
		oidcConfig:    oidcConfig,
		provider:      oidcProvider,
		decryptionKey: &localKey,
		remoteKeySet:  remoteKeySet,
		config:        config,
		ctx:           ctx,
	}, nil
}

// Tokens combines both the oauth2 token and the oidc specific idToken
type Tokens struct {
	Oauth2Token *oauth2.Token
	IdToken     *oidc.IDToken
}

// OIDCClient wraps oauth2 and go-oidc libraries and provides
// convenience functions for implementing OIDC authorization code flow.
type OIDCClient struct {
	oauth2Config *oauth2.Config
	oidcConfig   *oidc.Config
	provider     *oidc.Provider
	config       *Config
	ctx          context.Context
}

// Exchange exchanges the authorization code to a token.
func (o *OIDCClient) Exchange(code string, options map[string]string) (*Tokens, error) {
	var opts []oauth2.AuthCodeOption
	for key, value := range options {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}
	oauth2Token, err := o.oauth2Config.Exchange(o.ctx, code, opts...)
	if err != nil {
		return nil, errors.New("unable to exchange code for token")
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token field in oauth2 token")
	}

	idToken, err := o.Verify(rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("unable to verify signature")
	}
	return &Tokens{
		Oauth2Token: oauth2Token,
		IdToken:     idToken,
	}, nil
}

// ExchangeWithNonce exchanges the authorization code to a token and verifies the nonce
func (o *OIDCClient) ExchangeWithNonce(code, nonce string, options map[string]string) (*Tokens, error) {
	tokens, err := o.Exchange(code, options)
	if err != nil {
		return nil, err
	}

	if tokens.IdToken.Nonce != nonce {
		return nil, fmt.Errorf("nonce is not the one specified. expected '%s', got '%s'", nonce, tokens.IdToken.Nonce)
	}

	return tokens, nil
}

// AuthRequestURL returns the URL for authorization request.
func (o *OIDCClient) AuthRequestURL(state string, options map[string]interface{}) (string, error) {
	var opts []oauth2.AuthCodeOption
	for key, value := range options {
		switch valueType := value.(type) {
		case []string:
			list := strings.Join(value.([]string), " ")
			opts = append(opts, oauth2.SetAuthURLParam(key, list))
		case string:
			opts = append(opts, oauth2.SetAuthURLParam(key, value.(string)))
		default:
			return "", fmt.Errorf("unknown request option type: '%T'", valueType)
		}
	}

	return o.oauth2Config.AuthCodeURL(state, opts...), nil
}

// Verify verifies the signature of the token. Note that the possible nonce in
// the token is not verified; use ExchangeWithNonce for nonce validation.
func (o *OIDCClient) Verify(token string) (*oidc.IDToken, error) {
	verifier := o.provider.Verifier(o.oidcConfig)
	return verifier.Verify(o.ctx, token)
}

// UserInfo fetches user information from provider's user info endpoint.
func (o *OIDCClient) UserInfo(token oauth2.TokenSource, user interface{}) error {
	userInfo, err := o.provider.UserInfo(o.ctx, token)
	if err != nil {
		return fmt.Errorf("unable to fetch user info: %w", err)
	}
	err = userInfo.Claims(&user)
	if err != nil {
		return fmt.Errorf("unable to marshal claims: %w", err)
	}
	return nil
}

// HandleCallback is a convenience function which exchanges the authorization
// code to token and then uses the token to request user information from user
// info endpoint. The implementation does not use message level encryption.
func (o *OIDCClient) HandleCallback(state, nonce string, queryParams url.Values, user interface{}) error {
	if len(queryParams.Get("error")) > 0 {
		err := queryParams.Get("error")
		errDescription := queryParams.Get("error_description")
		return fmt.Errorf("authorization failed. error: %s, description: %s", err, errDescription)
	}

	if queryParams.Get("state") != state {
		return errors.New("received state does not match the defined state")
	}

	code := queryParams.Get("code")
	if code == "" {
		return errors.New("authorization code missing")
	}
	options := map[string]string{
		"client_id": o.oauth2Config.ClientID,
	}

	var (
		tokens *Tokens
		err    error
	)
	if nonce != "" {
		tokens, err = o.ExchangeWithNonce(code, nonce, options)
	} else {
		tokens, err = o.Exchange(code, options)
	}
	if err != nil {
		return err
	}

	return o.UserInfo(oauth2.StaticTokenSource(tokens.Oauth2Token), &user)
}

// OIDCClientEncrypted wraps oauth2 and oidc libraries and provides
// convenience functions for implementing OIDC authentication. The difference
// between OIDCClientEncrypted and OIDCClient is that the former uses message
// level encryption when communicating with the service provider.
type OIDCClientEncrypted struct {
	oauth2Config  *oauth2.Config
	oidcConfig    *oidc.Config
	provider      *oidc.Provider
	decryptionKey *jose.JSONWebKey
	remoteKeySet  *RemoteKeyStore
	config        *Config
	ctx           context.Context
}

// AuthRequestURL returns the authorization request URL with encrypted request object.
func (o *OIDCClientEncrypted) AuthRequestURL(state string, opts map[string]interface{}) (string, error) {
	mandatoryParams := map[string]string{
		"response_type": "code",
		"client_id":     o.oauth2Config.ClientID,
		"redirect_uri":  o.oauth2Config.RedirectURL,
		"scope":         strings.Join(o.oauth2Config.Scopes, " "),
		"state":         state,
	}

	// This will override any options that conflict with mandatory params
	for key, value := range mandatoryParams {
		opts[key] = value
	}

	requestPayload, err := json.Marshal(opts)
	if err != nil {
		return "", err
	}

	encryptionKey, err := o.remoteKeySet.ByUse("enc")
	if err != nil {
		return "", err
	}

	// TODO: take encryption algorithm from openid-configuration
	enc := jose.ContentEncryption("A256CBC-HS512")
	alg := jose.KeyAlgorithm(encryptionKey.Algorithm)
	options := jose.EncrypterOptions{
		Compression:  "",
		ExtraHeaders: nil,
	}
	options.WithType("JWE")
	encrypter, err := newEncrypter(o.ctx, encryptionKey, enc, alg, options)
	if err != nil {
		return "", err
	}

	data, err := encrypter.Encrypt(requestPayload)
	if err != nil {
		return "", err
	}

	serializedRequestObject, err := data.CompactSerialize()
	if err != nil {
		return "", err
	}

	authRequestURL := fmt.Sprintf("%s?request=%s", o.oauth2Config.Endpoint.AuthURL, serializedRequestObject)
	return authRequestURL, nil
}

// Verify verifies the signature of a token.
func (o *OIDCClientEncrypted) Verify(token string) (*oidc.IDToken, error) {
	verifier := o.provider.Verifier(o.oidcConfig)
	return verifier.Verify(o.ctx, token)
}

// Exchange exchanges the authorization code to a token.
func (o *OIDCClientEncrypted) Exchange(code string, options map[string]string) (*Tokens, error) {
	var opts []oauth2.AuthCodeOption
	for key, value := range options {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}
	oauth2Token, err := o.oauth2Config.Exchange(o.ctx, code, opts...)
	if err != nil {
		return nil, errors.New("unable to exchange authorization code to token")
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token field in oauth2 token")
	}

	parsedJWE, err := jose.ParseEncrypted(rawIDToken)
	if err != nil {
		return nil, errors.New("unable to parse encrypted id_token")
	}

	decryptedIdToken, err := parsedJWE.Decrypt(o.decryptionKey)
	if err != nil {
		return nil, errors.New("unable to decrypt id_token")
	}

	idToken, err := o.Verify(string(decryptedIdToken))
	if err != nil {
		return nil, errors.New("unable to verify id_token signature")
	}

	return &Tokens{
		Oauth2Token: oauth2Token,
		IdToken:     idToken,
	}, nil
}

// ExchangeWithNonce Exchanges the authorization code to a token and verifies nonce
func (o *OIDCClientEncrypted) ExchangeWithNonce(code, nonce string, options map[string]string) (*Tokens, error) {
	tokens, err := o.Exchange(code, options)
	if err != nil {
		return nil, err
	}

	if tokens.IdToken.Nonce != nonce {
		return nil, fmt.Errorf("nonce is not the one specified. expected '%s', got '%s'", nonce, tokens.IdToken.Nonce)
	}
	return tokens, nil
}

// providerEndpoints represents the provider's OIDC endpoints.
type providerEndpoints struct {
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	JwksURL     string `json:"jwks_uri"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

// UserInfo fetches user information from provider's user info endpoint.
func (o *OIDCClientEncrypted) UserInfo(tokenSource oauth2.TokenSource, destination interface{}) error {
	var endpoints providerEndpoints
	err := o.provider.Claims(&endpoints)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("GET", endpoints.UserInfoURL, nil)
	if err != nil {
		return fmt.Errorf("unable to create userinfo request: %w", err)
	}

	token, err := tokenSource.Token()
	if err != nil {
		return fmt.Errorf("unable to get token: %w", err)
	}
	token.SetAuthHeader(req)

	response, err := doRequest(o.ctx, req)
	if err != nil {
		return fmt.Errorf("unable to execute request: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %w", err)
	}
	if !statusCodeIs2xx(response.StatusCode) {
		return fmt.Errorf("unable to fetch user info, received status: %s", response.Status)
	}

	webToken, err := jwt.ParseSignedAndEncrypted(string(body))
	if err != nil {
		return fmt.Errorf("unable to parse encrypted response: %w", err)
	}

	decryptedData, err := webToken.Decrypt(o.decryptionKey)
	if err != nil {
		return fmt.Errorf("unable to decrypt payload: %w", err)
	}

	verificationKey, err := o.remoteKeySet.ById(decryptedData.Headers[0].KeyID)
	if err != nil {
		return fmt.Errorf("unable to find key with keyId '%s'", decryptedData.Headers[0].KeyID)
	}
	err = decryptedData.Claims(verificationKey, destination)
	if err != nil {
		return err
	}
	return nil
}

// HandleCallback is a convenience function which exchanges the authorization
// code to token and then uses the token to request user information from
// user info endpoint. The implementation uses message level encryption.
func (o *OIDCClientEncrypted) HandleCallback(state, nonce string, queryParams url.Values, user interface{}) error {
	if len(queryParams.Get("error")) > 0 {
		err := queryParams.Get("error")
		errDescription := queryParams.Get("error_description")
		return fmt.Errorf("authorization failed. error: %s, description: %s", err, errDescription)
	}

	if queryParams.Get("state") != state {
		return errors.New("received state does not match the defined state")
	}

	code := queryParams.Get("code")
	if len(code) == 0 {
		return errors.New("authorization code missing")
	}
	options := map[string]string{
		"client_id": o.oauth2Config.ClientID,
	}

	var (
		tokens *Tokens
		err    error
	)
	if nonce != "" {
		tokens, err = o.ExchangeWithNonce(code, nonce, options)
	} else {
		tokens, err = o.Exchange(code, options)
	}
	if err != nil {
		return err
	}

	return o.UserInfo(oauth2.StaticTokenSource(tokens.Oauth2Token), &user)
}
