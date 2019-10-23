package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Jwks tests", func() {
	Describe("ByUse", func() {
		It("Finds a key from keyset by use", func() {
			key1, _ := generateKey("example1", "RSA-OAEP", "enc")
			key2, _ := generateKey("example2", "RSA-OAEP", "sig")
			keyset := JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					*key1,
					*key2,
				},
			}

			Expect(keyset.ByUse("enc")).To(Equal(key1))
			Expect(keyset.ByUse("sig")).To(Equal(key2))
		})

		It("Throws an error if no keys by usage are found", func() {
			key1, _ := generateKey("example1", "RSA-OAEP", "enc")
			keyset := JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					*key1,
				},
			}

			_, err := keyset.ByUse("sig")
			Expect(err).ShouldNot(BeNil())
			Expect(err).To(Equal(errors.New("key not found")))
		})
	})

	Describe("ById", func() {
		It("Finds a key from keyset by use", func() {
			key1, _ := generateKey("example1", "RSA-OAEP", "enc")
			key2, _ := generateKey("example2", "RSA-OAEP", "sig")
			keyset := JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					*key1,
					*key2,
				},
			}

			Expect(keyset.ById("example1")).To(Equal(key1))
			Expect(keyset.ById("example2")).To(Equal(key2))
		})

		It("Throws an error if no keys by usage are found", func() {
			key1, _ := generateKey("example1", "RSA-OAEP", "enc")
			keyset := JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					*key1,
				},
			}

			_, err := keyset.ById("notReal")
			Expect(err).ShouldNot(BeNil())
			Expect(err).To(Equal(errors.New("key not found")))
		})
	})

	Describe("updateKeys", func() {
		It("updates the keys successfully", func() {
			signKeyId := generateId()
			signKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			signKeyJwk := &jose.JSONWebKey{Key: signKey.Public(), Certificates: []*x509.Certificate{}, KeyID: signKeyId, Algorithm: "RS256", Use: "sig"}
			signKeyJwk.Certificates = nil
			signKeyMarshaled, err := signKeyJwk.MarshalJSON()
			if err != nil {
				Fail("unable to marshal generated public signKey")
			}

			encKeyId := generateId()
			encKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			encKeyJwk := &jose.JSONWebKey{Key: encKey.Public(), Certificates: []*x509.Certificate{}, KeyID: encKeyId, Algorithm: "RSA-OAEP", Use: "enc"}
			encKeyMarshaled, err := encKeyJwk.MarshalJSON()
			if err != nil {
				Fail("unable to marshal generated public signKey")
			}

			body := fmt.Sprintf(`{"keys":[%s, %s]}`, signKeyMarshaled, encKeyMarshaled)
			mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				return newMockResponse(http.StatusOK, headers, body), nil
			})

			var expectedKeySet jose.JSONWebKeySet
			err = json.Unmarshal([]byte(body), &expectedKeySet)
			if err != nil {
				Fail("failed to unmarshal expected key set")
			}

			ctx := context.Background()
			ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
			const uri = "https://example.com/oidc/jwks.json"
			jwks, expiry, err := updateKeys(ctxWithClient, uri)

			now := time.Now()
			Expect(jwks).To(Equal(expectedKeySet.Keys))
			Expect(expiry).Should(BeTemporally("<=", now))
			Expect(err).To(BeNil())
		})

		It("fails when request cannot be created", func() {
			invalidUri := string([]byte{0x7f})
			jwks, expiry, err := updateKeys(nil, invalidUri)

			expectedError := "unable to create request: parse \u007f: net/url: invalid control character in URL"
			Expect(jwks).To(BeNil())
			Expect(expiry).To(Equal(time.Time{}))
			Expect(err.Error()).To(Equal(expectedError))
		})

		It("fails when request to uri fails", func() {
			mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
				return &http.Response{}, errors.New("request failed")
			})

			ctx := context.Background()
			ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
			const uri = "https://example.com/oidc/jwks.json"
			jwks, expiry, err := updateKeys(ctxWithClient, uri)

			expectedError := "unable to fetch keys Get https://example.com/oidc/jwks.json: request failed"
			Expect(jwks).To(BeNil())
			Expect(expiry).To(Equal(time.Time{}))
			Expect(err.Error()).To(Equal(expectedError))
		})

		It("fails when response is not HTTP 200", func() {
			body := `{"error": "internal server error"}`
			mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				return newMockResponse(http.StatusInternalServerError, headers, body), nil
			})

			ctx := context.Background()
			ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
			const uri = "https://example.com/oidc/jwks.json"
			jwks, expiry, err := updateKeys(ctxWithClient, uri)

			fmt.Println(err.Error())

			expectedError := fmt.Sprintf("unable to get keys: %s %s", http.StatusText(http.StatusInternalServerError), body)
			Expect(jwks).To(BeNil())
			Expect(expiry).To(Equal(time.Time{}))
			Expect(err.Error()).To(Equal(expectedError))
		})

		It("fails when response cache headers cannot be parsed", func() {
			signKeyId := generateId()
			signKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			signKeyJwk := &jose.JSONWebKey{Key: signKey.Public(), Certificates: []*x509.Certificate{}, KeyID: signKeyId, Algorithm: "RS256", Use: "sig"}
			signKeyJwk.Certificates = nil
			signKeyMarshaled, err := signKeyJwk.MarshalJSON()
			if err != nil {
				Fail("unable to marshal generated public signKey")
			}

			encKeyId := generateId()
			encKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			encKeyJwk := &jose.JSONWebKey{Key: encKey.Public(), Certificates: []*x509.Certificate{}, KeyID: encKeyId, Algorithm: "RSA-OAEP", Use: "enc"}
			encKeyMarshaled, err := encKeyJwk.MarshalJSON()
			if err != nil {
				Fail("unable to marshal generated public signKey")
			}

			body := fmt.Sprintf(`{"keys":[%s, %s]}`, signKeyMarshaled, encKeyMarshaled)
			mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type":  {"application/json"},
					"Cache-Control": {"max-age=INVALID"},
				}
				return newMockResponse(http.StatusOK, headers, body), nil
			})

			ctx := context.Background()
			ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
			const uri = "https://example.com/oidc/jwks.json"
			jwks, expiry, err := updateKeys(ctxWithClient, uri)

			fmt.Println(err.Error())

			expectedError := `unable to parse response cache headers: strconv.ParseUint: parsing "INVALID": invalid syntax`
			Expect(jwks).To(BeNil())
			Expect(expiry).To(Equal(time.Time{}))
			Expect(err.Error()).To(Equal(expectedError))
		})

		It("sets the expiration correctly from response cache control headers", func() {
			signKeyId := generateId()
			signKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			signKeyJwk := &jose.JSONWebKey{Key: signKey.Public(), Certificates: []*x509.Certificate{}, KeyID: signKeyId, Algorithm: "RS256", Use: "sig"}
			signKeyJwk.Certificates = nil
			signKeyMarshaled, err := signKeyJwk.MarshalJSON()
			if err != nil {
				Fail("unable to marshal generated public signKey")
			}

			encKeyId := generateId()
			encKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			encKeyJwk := &jose.JSONWebKey{Key: encKey.Public(), Certificates: []*x509.Certificate{}, KeyID: encKeyId, Algorithm: "RSA-OAEP", Use: "enc"}
			encKeyMarshaled, err := encKeyJwk.MarshalJSON()
			if err != nil {
				Fail("unable to marshal generated public signKey")
			}

			body := fmt.Sprintf(`{"keys":[%s, %s]}`, signKeyMarshaled, encKeyMarshaled)
			mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type":  {"application/json"},
					"Cache-Control": {"max-age=3600"},
				}
				return newMockResponse(http.StatusOK, headers, body), nil
			})

			var expectedKeySet jose.JSONWebKeySet
			err = json.Unmarshal([]byte(body), &expectedKeySet)
			if err != nil {
				Fail("failed to unmarshal expected key set")
			}
			now := time.Now()

			ctx := context.Background()
			ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
			const uri = "https://example.com/oidc/jwks.json"
			jwks, expiry, err := updateKeys(ctxWithClient, uri)

			Expect(jwks).To(Equal(expectedKeySet.Keys))
			Expect(expiry).Should(BeTemporally(">", now))
			Expect(expiry).Should(BeTemporally("<=", now.Add(1*time.Hour+1*time.Second)))
			Expect(err).To(BeNil())
		})
	})
})

func generateKey(keyId, alg, use string) (*jose.JSONWebKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &jose.JSONWebKey{Key: key, KeyID: keyId, Algorithm: alg, Use: use}, nil
}
