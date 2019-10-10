package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// OIDCInterface is a common interface for OIDC clients to implement.
type OIDCInterface interface {
	Exchange(context.Context, string, map[string]string) (*oauth2.Token, error)
	AuthRequestURL(string, map[string]string) (string, error)
	Verify(string) (*oidc.IDToken, error)
	UserInfo(context.Context, oauth2.TokenSource, interface{}) error
	HandleCallback(context.Context, string, interface{}) error
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

	parsedRemotePubEncKey, err := remoteKeySet.ByUse("enc")
	if err != nil {
		return nil, err
	}
	parsedRemotePubSignKey, err := remoteKeySet.ByUse("sig")
	if err != nil {
		return nil, err
	}

	encrypter, err := newEncrypter(parsedRemotePubEncKey)
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
		oauth2Config:    &oauth2Config,
		oidcConfig:      oidcConfig,
		provider:        oidcProvider,
		encrypter:       encrypter,
		decryptionKey:   &localKey,
		verificationKey: parsedRemotePubSignKey,
		config:          config,
	}, nil
}

// OIDCClient wraps oaut2 and oidc libraries and provides convenience functions for implementing OIDC authentication.
type OIDCClient struct {
	oauth2Config *oauth2.Config
	oidcConfig   *oidc.Config
	provider     *oidc.Provider
	config       *Config
}

// Exchange exchanges the authorization code to a token.
func (o *OIDCClient) Exchange(ctx context.Context, code string, options map[string]string) (*oauth2.Token, error) {
	var opts []oauth2.AuthCodeOption
	for key, value := range options {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}
	oauth2Token, err := o.oauth2Config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, errors.New("unable to exchange code for token")
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token field in oauth2 token")
	}

	_, err = o.Verify(rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("unable to verify id_token")
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
	ctx := context.Background()
	return verifier.Verify(ctx, token)
}

// UserInfo fetches user information.
func (o *OIDCClient) UserInfo(ctx context.Context, token oauth2.TokenSource, user interface{}) error {
	userInfo, err := o.provider.UserInfo(ctx, token)
	if err != nil {
		log.Println("unable to fetch user info:", err.Error())
		return err
	}
	err = userInfo.Claims(&user)
	if err != nil {
		log.Println("unable to marshal claims", err.Error())
		return err
	}
	return nil
}

// HandleCallback is a convenience function which exchanges the authorization code to token and then uses the token
// to request user information from user info endpoint. The implementation does not use message level encryption.
func (o *OIDCClient) HandleCallback(ctx context.Context, code string, user interface{}) error {
	options := map[string]string{
		"client_id": o.oauth2Config.ClientID,
	}
	oauth2Token, err := o.Exchange(ctx, code, options)
	if err != nil {
		return err
	}

	return o.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token), &user)
}

// OIDCClientEncrypted wraps oauth2 and oidc libraries and provides convenience functions for implementing OIDC
// authentication. The difference between OIDCClientEncrypted and OIDCClient is that the former uses message level
// encryption when communicating with the service provider.
type OIDCClientEncrypted struct {
	oauth2Config    *oauth2.Config
	oidcConfig      *oidc.Config
	provider        *oidc.Provider
	encrypter       jose.Encrypter
	decryptionKey   *jose.JSONWebKey
	verificationKey *jose.JSONWebKey
	config          *Config
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

	data, err := o.encrypter.Encrypt(requestJSON)
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
	ctx := context.Background()
	return verifier.Verify(ctx, token)
}

// Exchange exchanges the authorization code to a token.
func (o *OIDCClientEncrypted) Exchange(ctx context.Context, code string, options map[string]string) (*oauth2.Token, error) {
	var opts []oauth2.AuthCodeOption
	for key, value := range options {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}
	oauth2Token, err := o.oauth2Config.Exchange(ctx, code, opts...)
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
func (o *OIDCClientEncrypted) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource, dest interface{}) error {
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

	response, err := doRequest(ctx, req)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if statusCode := response.StatusCode; statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("unable to fetch authorization token. received status code: %d", statusCode)
	}

	webToken, err := jwt.ParseSignedAndEncrypted(string(body))
	if err != nil {
		return err
	}

	decryptedData, err := webToken.Decrypt(o.decryptionKey)
	if err != nil {
		return err
	}

	err = decryptedData.Claims(o.verificationKey, dest)
	if err != nil {
		return err
	}
	return nil
}

// HandleCallback is a convenience function which exchanges the authorization code to token and then uses the token
// to request user information from user info endpoint. The implementation uses message level encryption.
func (o *OIDCClientEncrypted) HandleCallback(ctx context.Context, code string, user interface{}) error {
	options := map[string]string{
		"client_id": o.oauth2Config.ClientID,
	}
	oauth2Token, err := o.Exchange(ctx, code, options)
	if err != nil {
		return err
	}

	return o.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token), &user)
}
