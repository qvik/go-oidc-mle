package oidc

import (
	"errors"

	"gopkg.in/square/go-jose.v2"
)

// JSONWebKeySet represents a JWK Set object.
type JSONWebKeySet struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

// Key convenience method returns keys by key ID. Specification states
// that a JWK Set "SHOULD" use distinct key IDs, but allows for some
// cases where they are not distinct. Hence method returns a slice
// of JSONWebKeys.
func (s *JSONWebKeySet) Key(kid string) []jose.JSONWebKey {
	var keys []jose.JSONWebKey
	for _, key := range s.Keys {
		if key.KeyID == kid {
			keys = append(keys, key)
		}
	}

	return keys
}

// Convenience method for getting key(s) from keyset by use
func (s *JSONWebKeySet) ByUse(use string) (*jose.JSONWebKey, error) {
	for _, key := range s.Keys {
		if key.Use == use {
			return &key, nil
		}
	}

	return nil, errors.New("key not found")
}
