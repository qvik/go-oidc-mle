package oidc

import (
	"context"
	"net/http"

	"gopkg.in/square/go-jose.v2"
)

const EncrypterContextKey string = "EncrypterContextKey"

// Scope value that the client uses to request openid connect authentication
const scopeOpenID string = "openid"

// TODO(janne): find a better way to enable mocking with go-jose
// mockEncrypter is only used to enable mocking the jose.Encrypter for testing
// purposes. However, we need to define it here to be able to get the value
// from the context during runtime.
type mockEncrypter struct {
	encryption jose.JSONWebEncryption
	opts       jose.EncrypterOptions
	error      error
}

func (m *mockEncrypter) Encrypt(plaintext []byte) (*jose.JSONWebEncryption, error) {
	if m.error != nil {
		return nil, m.error
	}
	return &m.encryption, nil
}

func (m *mockEncrypter) EncryptWithAuthData(plaintext []byte, aad []byte) (*jose.JSONWebEncryption, error) {
	if m.error != nil {
		return nil, m.error
	}
	return &m.encryption, nil
}

func (m *mockEncrypter) Options() jose.EncrypterOptions {
	return m.opts
}

// newEncrypted is a convenience method for creating a jose.Encrypter using a specified JWK.
func newEncrypter(ctx context.Context, key *jose.JSONWebKey, enc jose.ContentEncryption, alg jose.KeyAlgorithm, options jose.EncrypterOptions) (jose.Encrypter, error) {
	encrypter, err := jose.NewEncrypter(enc, jose.Recipient{
		Algorithm: alg,
		Key:       key,
	}, &options)
	if err != nil {
		return nil, err
	}

	if e, ok := ctx.Value(EncrypterContextKey).(mockEncrypter); ok {
		return &e, nil
	}
	return encrypter, nil
}

// Checks if the status code is between 200 and 299 range inclusive.
func statusCodeIs2xx(statusCode int) bool {
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return false
	}
	return true
}

// Adds "openid" to the scope if not present
func addOpenIdToScope(scope []string) []string {
	for _, value := range scope {
		if value == scopeOpenID {
			return scope
		}
	}

	return append([]string{scopeOpenID}, scope...)
}
