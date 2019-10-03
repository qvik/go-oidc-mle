package oidc

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"gopkg.in/square/go-jose.v2"
)

func newEncrypter(key *jose.JSONWebKey) (jose.Encrypter, error) {
	alg := jose.KeyAlgorithm("RSA-OAEP")
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

func providerRemoteKeys(jwksUri string) (*JSONWebKeySet, error) {
	response, err := http.Get(jwksUri)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch jwks: %v", err.Error())
	}
	defer response.Body.Close()

	type jwksJSON struct {
		Keys []jose.JSONWebKey `json:"keys"`
	}
	var jwks jwksJSON
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err.Error())
	}
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
