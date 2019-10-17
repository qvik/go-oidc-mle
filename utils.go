package oidc

import (
	"net/http"

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

// statusCodeIs2xx checks if the status code is between 200 and 299 range inclusive.
func statusCodeIs2xx(statusCode int) bool {
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return false
	}
	return true
}
