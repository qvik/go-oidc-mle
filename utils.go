package oidc

import (
	"context"
	"net/http"

	"gopkg.in/square/go-jose.v2"
)

const EncrypterContextKey string = "EncrypterContextKey"

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
func newEncrypter(ctx context.Context, key *jose.JSONWebKey) (jose.Encrypter, error) {
	// TODO(janne): the encryption algorithm should be taken from the oidc-configuration
	enc := jose.ContentEncryption("A256CBC-HS512")
	alg := jose.KeyAlgorithm(key.Algorithm)
	options := jose.EncrypterOptions{
		Compression:  "",
		ExtraHeaders: nil,
	}
	options.WithType("JWE")

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
