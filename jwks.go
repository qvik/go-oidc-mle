package oidc

import (
	"errors"

	"gopkg.in/square/go-jose.v2"
)

// JSONWebKeySet represents a JWK key set. We are not using jose.JSONWebKeySet directly as we need ByUse function.
type JSONWebKeySet jose.JSONWebKeySet

// ById returns keys by key ID from the key set
func (s *JSONWebKeySet) ById(kid string) (*jose.JSONWebKey, error) {
	for _, key := range s.Keys {
		if key.KeyID == kid {
			return &key, nil
		}
	}

	return nil, errors.New("key not found")
}

// Convenience method for getting key(s) from key set by use
func (s *JSONWebKeySet) ByUse(use string) (*jose.JSONWebKey, error) {
	for _, key := range s.Keys {
		if key.Use == use {
			return &key, nil
		}
	}

	return nil, errors.New("key not found")
}
