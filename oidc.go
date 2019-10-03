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

type OIDCInterface interface {
	Exchange(string, map[string]string) (*oauth2.Token, error)
	AuthRequestURL(string, map[string]string) (string, error)
	Verify(string) (*oidc.IDToken, error)
	UserInfo(oauth2.TokenSource, interface{}) error
	HandleCallback(string, interface{}) error
}

func Must(client OIDCInterface, err error) OIDCInterface {
	if err != nil {
		panic(err)
	}

	return client
}

func NewClient(ctx context.Context, config *Config) (*OIDCClient, error) {
	oidcProvider, err := oidc.NewProvider(ctx, config.Endpoint)
	if err != nil {
		return nil, err
	}

	oidcConfig := &oidc.Config{
		ClientID: config.ClientId,
	}

	oauth2Endpoint := oidcProvider.Endpoint()
	oauth2Config := oauth2.Config{
		ClientID:     config.ClientId,
		ClientSecret: config.ClientSecret,
		Endpoint:     oauth2Endpoint,
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

func NewClientMLE(ctx context.Context, config *Config) (*OIDCClientEncrypted, error) {
	oidcProvider, err := oidc.NewProvider(ctx, config.Endpoint)
	if err != nil {
		return nil, err
	}

	type jwksUriJSON struct {
		Uri string `json:"jwks_uri"`
	}

	var jwksUri jwksUriJSON
	err = oidcProvider.Claims(&jwksUri)
	if err != nil {
		return nil, err
	}

	remoteKeySet, err := providerRemoteKeys(jwksUri.Uri)
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
	oauth2Endpoint := oidcProvider.Endpoint()
	oauth2Config := oauth2.Config{
		ClientID:     config.ClientId,
		ClientSecret: config.ClientSecret,
		Endpoint:     oauth2Endpoint,
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

type OIDCClient struct {
	oauth2Config *oauth2.Config
	oidcConfig   *oidc.Config
	provider     *oidc.Provider
	config       *Config
}

func (o *OIDCClient) Exchange(code string, options map[string]string) (*oauth2.Token, error) {
	var opts []oauth2.AuthCodeOption
	for key, value := range options {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}
	ctx := context.Background()
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

// AuthRequestURL returns the URL for authorization request
func (o *OIDCClient) AuthRequestURL(state string, options map[string]string) (string, error) {
	var opts []oauth2.AuthCodeOption
	for key, value := range options {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}
	return o.oauth2Config.AuthCodeURL(state, opts...), nil
}

func (o *OIDCClient) Verify(token string) (*oidc.IDToken, error) {
	verifier := o.provider.Verifier(o.oidcConfig)
	ctx := context.Background()
	return verifier.Verify(ctx, token)
}

// UserInfo fetches user information but does not use message level encryption
func (o *OIDCClient) UserInfo(token oauth2.TokenSource, user interface{}) error {
	ctx := context.Background()
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

// UserInfo fetches user information but does not use message level encryption
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

type OIDCClientEncrypted struct {
	oauth2Config    *oauth2.Config
	oidcConfig      *oidc.Config
	provider        *oidc.Provider
	encrypter       jose.Encrypter
	decryptionKey   *jose.JSONWebKey
	verificationKey *jose.JSONWebKey
	config          *Config
}

// AuthCodeURLEncrypted returns the authorization request with encrypted request object
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

// Verify verifies the id_token
func (o *OIDCClientEncrypted) Verify(token string) (*oidc.IDToken, error) {
	verifier := o.provider.Verifier(o.oidcConfig)
	ctx := context.Background()
	return verifier.Verify(ctx, token)
}

func (o *OIDCClientEncrypted) Exchange(code string, options map[string]string) (*oauth2.Token, error) {
	var opts []oauth2.AuthCodeOption
	for key, value := range options {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}
	ctx := context.Background()
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

// UserInfo fetches user information from client provider
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

	response, err := http.DefaultClient.Do(req)
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
