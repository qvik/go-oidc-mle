package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// OIDCInterface is a common interface for OIDC clients to implement.
type OIDCInterface interface {
	Exchange(string, map[string]string) (*oauth2.Token, error)
	AuthRequestURL(string, map[string]string) (string, error)
	Verify(string) (*oidc.IDToken, error)
	UserInfo(oauth2.TokenSource, interface{}) error
	HandleCallback(string, interface{}) error
}

// Must is a convenience function to make sure that the OIDC client is successfully initialised or it panics.
func Must(client OIDCInterface, err error) OIDCInterface {
	if err != nil {
		panic(err)
	}

	return client
}

// NewClient initialises OIDClient and returns a pointer to the instance.
func NewClient(ctx context.Context, config *Config) (*OIDCClient, error) {
	oidcProvider, err := oidc.NewProvider(ctx, config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize client: %v", err.Error())
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

// NewClientMLE initialises OIDClientEncrypted and returns a pointer to the instance.
func NewClientMLE(ctx context.Context, config *Config) (*OIDCClientEncrypted, error) {
	oidcProvider, err := oidc.NewProvider(ctx, config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize client: %v", err.Error())
	}

	type jwksUriJSON struct {
		Uri string `json:"jwks_uri"`
	}

	var jwksUri jwksUriJSON
	err = oidcProvider.Claims(&jwksUri)
	if err != nil {
		return nil, err
	}

	remoteKeySet, err := providerRemoteKeys(ctx, jwksUri.Uri)
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
	err = json.Unmarshal([]byte(config.MleKey), &localKey)
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

// OIDCClient wraps oaut2 and oidc libraries and provides convenience functions for implementing OIDC authentication.
type OIDCClient struct {
	oauth2Config *oauth2.Config
	oidcConfig   *oidc.Config
	provider     *oidc.Provider
	config       *Config
	ctx          context.Context
}

// Exchange exchanges the authorization code to a token.
func (o *OIDCClient) Exchange(code string, options map[string]string) (*oauth2.Token, error) {
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

	_, err = o.Verify(rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("unable to verify signature")
	}
	return oauth2Token, nil
}

// AuthRequestURL returns the URL for authorization request.
func (o *OIDCClient) AuthRequestURL(state string, options map[string]string) (string, error) {
	var opts []oauth2.AuthCodeOption
	for key, value := range options {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}
	return o.oauth2Config.AuthCodeURL(state, opts...), nil
}

// Verify verifies the signature of the token.
func (o *OIDCClient) Verify(token string) (*oidc.IDToken, error) {
	verifier := o.provider.Verifier(o.oidcConfig)
	return verifier.Verify(o.ctx, token)
}

// UserInfo fetches user information.
func (o *OIDCClient) UserInfo(token oauth2.TokenSource, user interface{}) error {
	userInfo, err := o.provider.UserInfo(o.ctx, token)
	if err != nil {
		return fmt.Errorf("unable to fetch user info: %v", err.Error())
	}
	err = userInfo.Claims(&user)
	if err != nil {
		return fmt.Errorf("unable to marshal claims: %v", err.Error())
	}
	return nil
}

// HandleCallback is a convenience function which exchanges the authorization code to token and then uses the token
// to request user information from user info endpoint. The implementation does not use message level encryption.
func (o *OIDCClient) HandleCallback(code string, user interface{}) error {
	options := map[string]string{
		"client_id": o.oauth2Config.ClientID,
	}
	oauth2Token, err := o.Exchange(code, options)
	if err != nil {
		return err
	}

	return o.UserInfo(oauth2.StaticTokenSource(oauth2Token), &user)
}

// OIDCClientEncrypted wraps oauth2 and oidc libraries and provides convenience functions for implementing OIDC
// authentication. The difference between OIDCClientEncrypted and OIDCClient is that the former uses message level
// encryption when communicating with the service provider.
type OIDCClientEncrypted struct {
	oauth2Config  *oauth2.Config
	oidcConfig    *oidc.Config
	provider      *oidc.Provider
	decryptionKey *jose.JSONWebKey
	remoteKeySet  *RemoteKeyStore
	config        *Config
	ctx           context.Context
}

// AuthCodeURLEncrypted returns the URL of the authorization request with encrypted request object.
func (o *OIDCClientEncrypted) AuthRequestURL(state string, opts map[string]string) (string, error) {
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

	requestJSON, err := json.Marshal(opts)
	if err != nil {
		return "", err
	}

	encryptionKey, err := o.remoteKeySet.ByUse("enc")
	if err != nil {
		return "", err
	}
	encrypter, err := newEncrypter(encryptionKey)
	if err != nil {
		return "", err
	}

	data, err := encrypter.Encrypt(requestJSON)
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

// Verify verifies the signature of a token
func (o *OIDCClientEncrypted) Verify(token string) (*oidc.IDToken, error) {
	verifier := o.provider.Verifier(o.oidcConfig)
	return verifier.Verify(o.ctx, token)
}

// Exchange exchanges the authorization code to a token.
func (o *OIDCClientEncrypted) Exchange(code string, options map[string]string) (*oauth2.Token, error) {
	var opts []oauth2.AuthCodeOption
	for key, value := range options {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}
	oauth2Token, err := o.oauth2Config.Exchange(o.ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch oauth2 token: %v", err.Error())
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token field in oauth2 token")
	}

	obj, err := jose.ParseEncrypted(rawIDToken)
	if err != nil {
		return nil, errors.New("unable to parse encrypted id_token")
	}

	decryptedIdToken, err := obj.Decrypt(o.decryptionKey)
	if err != nil {
		return nil, errors.New("unable to decrypt id_token")
	}

	_, err = o.Verify(string(decryptedIdToken))
	if err != nil {
		return nil, fmt.Errorf("unable to verify id_token: %v", err.Error())
	}
	return oauth2Token, nil
}

type userInfoURL struct {
	Endpoint string `json:"userinfo_endpoint"`
}

// UserInfo fetches user information from client provider.
func (o *OIDCClientEncrypted) UserInfo(tokenSource oauth2.TokenSource, dest interface{}) error {
	var userInfoURL userInfoURL
	err := o.provider.Claims(&userInfoURL)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("GET", userInfoURL.Endpoint, nil)
	if err != nil {
		return err
	}

	token, err := tokenSource.Token()
	if err != nil {
		return err
	}
	token.SetAuthHeader(req)

	response, err := doRequest(o.ctx, req)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if !statusCodeIs2xx(response.StatusCode) {
		return fmt.Errorf("unable to fetch authorization token. received status code: %d", response.StatusCode)
	}

	webToken, err := jwt.ParseSignedAndEncrypted(string(body))
	if err != nil {
		return err
	}

	decryptedData, err := webToken.Decrypt(o.decryptionKey)
	if err != nil {
		return err
	}

	verificationKey, err := o.remoteKeySet.ById(decryptedData.Headers[0].KeyID)
	if err != nil {
		return fmt.Errorf("unable to find key with keyId '%s'", decryptedData.Headers[0].KeyID)
	}
	err = decryptedData.Claims(verificationKey, dest)
	if err != nil {
		return err
	}
	return nil
}

// HandleCallback is a convenience function which exchanges the authorization code to token and then uses the token
// to request user information from user info endpoint. The implementation uses message level encryption.
func (o *OIDCClientEncrypted) HandleCallback(code string, user interface{}) error {
	options := map[string]string{
		"client_id": o.oauth2Config.ClientID,
	}
	oauth2Token, err := o.Exchange(code, options)
	if err != nil {
		return err
	}

	return o.UserInfo(oauth2.StaticTokenSource(oauth2Token), &user)
}
