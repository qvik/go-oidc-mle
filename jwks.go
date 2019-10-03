package oidc

import (
	"errors"

	"gopkg.in/square/go-jose.v2"
)

// JSONWebKeySet represents a JWK Set object.
type JSONWebKeySet struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

// ById returns keys by key ID
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
