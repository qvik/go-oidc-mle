package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/pquerna/cachecontrol"
	"golang.org/x/oauth2"
)

// RemoteKeyStore Stores OIDC provider's JWKs and caches them for the duration specified in
// the cache-control header. Keys will be refreshed upon expiry.
type RemoteKeyStore struct {
	jose.JSONWebKeySet
	Context context.Context
	JwksURI string
	Expiry  time.Time
	mutex   sync.Mutex
}

// ByUse returns a key from RemoteKeyStore by use. If the keystore contains
// multiple keys with same use then first key will be returned.
func (r *RemoteKeyStore) ByUse(use string) (*jose.JSONWebKey, error) {
	return r.find(func(key jose.JSONWebKey) bool { return key.Use == use })
}

// ById returns a key from RemoteKeyStore by key id. If the RemoteKeyStore
// contains multiple keys with same id then first matching key is returned.
func (r *RemoteKeyStore) ById(kid string) (*jose.JSONWebKey, error) {
	return r.find(func(key jose.JSONWebKey) bool { return key.KeyID == kid })
}

// find refreshes the keys if needed and returns the first key matching match.
// The returned key is a copy, so it stays valid after the next refresh.
func (r *RemoteKeyStore) find(match func(jose.JSONWebKey) bool) (*jose.JSONWebKey, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if err := r.refreshIfExpiring(); err != nil {
		return nil, err
	}

	for i := range r.Keys {
		if match(r.Keys[i]) {
			key := r.Keys[i]
			return &key, nil
		}
	}

	return nil, errors.New("key not found")
}

// refreshIfExpiring refreshes the cached keys if they expire within the next
// 10 minutes. The caller must hold r.mutex.
func (r *RemoteKeyStore) refreshIfExpiring() error {
	tenMinutesFromNow := time.Now().UTC().Add(10 * time.Minute)
	if tenMinutesFromNow.After(r.Expiry) {
		return r.updateKeys()
	}
	return nil
}

// updateKeys updates the keys and expiration in RemoteKeyStore. The caller
// must hold r.mutex.
func (r *RemoteKeyStore) updateKeys() error {
	keys, expiry, err := fetchKeys(r.Context, r.JwksURI)
	if err != nil {
		return err
	}
	r.Keys = keys
	r.Expiry = expiry
	return nil
}

// providerRemoteKeys is a convenience method for fetching and unmarshaling
// the provider JWKS from the jwks_uri. Returns a RemoteKeyStore containing
// the keys.
func providerRemoteKeys(ctx context.Context, jwksUri string) (*RemoteKeyStore, error) {
	keys, expiry, err := fetchKeys(ctx, jwksUri)
	if err != nil {
		return nil, err
	}
	return &RemoteKeyStore{
		JSONWebKeySet: jose.JSONWebKeySet{Keys: keys},
		Context:       ctx,
		JwksURI:       jwksUri,
		Expiry:        expiry,
	}, nil
}

// fetchKeys fetches the provider's JWKS from jwks_uri. The function respects
// cache headers and returns the expiry for the specified time period.
func fetchKeys(ctx context.Context, jwksUri string) ([]jose.JSONWebKey, time.Time, error) {
	req, err := http.NewRequest("GET", jwksUri, nil)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("unable to create request: %w", err)
	}

	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("unable to fetch keys: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("unable to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("unable to get keys: %s %s", resp.Status, body)
	}

	var keySet jose.JSONWebKeySet
	err = json.Unmarshal(body, &keySet)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("unable to unmarshal keys: %w", err)
	}

	expiry := time.Now().UTC()
	_, exp, err := cachecontrol.CachableResponse(req, resp, cachecontrol.Options{})
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("unable to parse response cache headers: %w", err)
	}
	if exp.After(expiry) {
		expiry = exp
	}
	return keySet.Keys, expiry, nil
}

// doRequest executes http request using either http.DefaultClient or the
// client specified in context if it's available.
func doRequest(ctx context.Context, request *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	return client.Do(request.WithContext(ctx))
}
