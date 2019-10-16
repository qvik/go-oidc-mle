package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
)

// newEncrypted is a convenience method for creating a jose.Encrypter using a JWK key.
func newEncrypter(key *jose.JSONWebKey) (jose.Encrypter, error) {
	alg := jose.KeyAlgorithm(key.Algorithm)
	// TODO(janne): the encryption algorithm should be taken from the oidc-configuration
	enc := jose.ContentEncryption("A256CBC-HS512")
	options := jose.EncrypterOptions{
		Compression:  "",
		ExtraHeaders: nil,
	}
	options.WithType("JWE")
	return jose.NewEncrypter(enc, jose.Recipient{
		Algorithm: alg,
		Key:       key,
	}, &options)
}

// providerRemoteKeys is a convenience method for fetching and unmashaling the provider jwks from the jwks_uri.
// Returns a JWSONWebKeySet containing the keys.
func providerRemoteKeys(ctx context.Context, jwksUri string) (*JSONWebKeySet, error) {
	req, err := http.NewRequest("GET", jwksUri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	type jwksJSON struct {
		Keys []jose.JSONWebKey `json:"keys"`
	}
	var jwks jwksJSON
	err = json.Unmarshal(body, &jwks)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal jwks: %v", err.Error())
	}

	if len(jwks.Keys) != 2 {
		log.Fatal("the number of remote keys is invalid. expected 2, got:", len(jwks.Keys))
	}

	return &JSONWebKeySet{
		Keys: jwks.Keys,
	}, nil
}

// doRequest executes http request using either http.DefaultClient or the client specified in context if it's available.
func doRequest(ctx context.Context, request *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	return client.Do(request.WithContext(ctx))
}

// statusCodeIs2xx checks if the status code is between 200 and 299 range inclusive.
func statusCodeIs2xx(statusCode int) bool {
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return false
	}
	return true
}
