package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pquerna/cachecontrol"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
)

const keysExpiryDelta = 15 * time.Second

// JSONWebKeySet represents a JWK key set. We are not using jose.JSONWebKeySet directly as we need ByUse function.
type JSONWebKeySet jose.JSONWebKeySet

// ById returns keys by key ID from the key set
func (j *JSONWebKeySet) ById(kid string) (*jose.JSONWebKey, error) {
	for _, key := range j.Keys {
		if key.KeyID == kid {
			return &key, nil
		}
	}

	return nil, errors.New("key not found")
}

// Convenience method for getting key(s) from key set by use
func (j *JSONWebKeySet) ByUse(use string) (*jose.JSONWebKey, error) {
	for _, key := range j.Keys {
		if key.Use == use {
			return &key, nil
		}
	}

	return nil, errors.New("key not found")
}

type RemoteKeyStore struct {
	JSONWebKeySet
	Context context.Context
	JwksURI string
	Expiry  time.Time
}

// providerRemoteKeys is a convenience method for fetching and unmashaling the provider jwks from the jwks_uri.
// Returns a JWSONWebKeySet containing the keys.
func providerRemoteKeys(ctx context.Context, jwksUri string) (*RemoteKeyStore, error) {
	keys, expiry, err := updateKeys(ctx, jwksUri)
	if err != nil {
		return nil, err
	}
	return &RemoteKeyStore{
		JSONWebKeySet: JSONWebKeySet{Keys: keys},
		Context:       ctx,
		JwksURI:       jwksUri,
		Expiry:        expiry,
	}, nil
}

func updateKeys(ctx context.Context, jwksUri string) ([]jose.JSONWebKey, time.Time, error) {
	req, err := http.NewRequest("GET", jwksUri, nil)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("unable to create request: %v", err)
	}

	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("unable to fetch keys %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("unable to get keys: %s %s", resp.Status, body)
	}

	var keySet jose.JSONWebKeySet
	err = json.Unmarshal(body, &keySet)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("unable to unmarshal keys: %v", err)
	}

	expiry := time.Now()
	_, exp, err := cachecontrol.CachableResponse(req, resp, cachecontrol.Options{})
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("unable to parse response cache headers: %v", err)
	}
	if exp.After(expiry) {
		expiry = exp
	}
	return keySet.Keys, expiry, nil
}

// doRequest executes http request using either http.DefaultClient or the client specified in context if it's available.
func doRequest(ctx context.Context, request *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	return client.Do(request.WithContext(ctx))
}
