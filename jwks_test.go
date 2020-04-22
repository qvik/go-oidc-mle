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
	const uri = "https://example.com/oidc/jwks.json"

	Describe("RemoteKeyStore", func() {
		var (
			signKeyId        string
			signKey          *rsa.PrivateKey
			signKeyJwk       *jose.JSONWebKey
			signKeyMarshaled []byte
			encKeyId         string
			encKey           *rsa.PrivateKey
			encKeyJwk        *jose.JSONWebKey
			encKeyMarshaled  []byte
			err              error
		)

		BeforeEach(func() {
			signKeyId = generateId()
			signKey, _ = rsa.GenerateKey(rand.Reader, 2048)
			signKeyJwk = &jose.JSONWebKey{
				Key:          signKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        signKeyId,
				Algorithm:    "RS256",
				Use:          "sig",
			}
			signKeyJwk.Certificates = nil
			signKeyMarshaled, err = signKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			encKeyId = generateId()
			encKey, _ = rsa.GenerateKey(rand.Reader, 2048)
			encKeyJwk = &jose.JSONWebKey{
				Key:          encKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        encKeyId,
				Algorithm:    "RSA-OAEP",
				Use:          "enc",
			}
			encKeyMarshaled, err = encKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())
		})

		Describe("ByUse", func() {
			It("successfully returns a key by usage from the key store", func() {
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
				Expect(err).To(BeNil())

				ctx := context.Background()
				ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
				remoteKeys, err := providerRemoteKeys(ctxWithClient, uri)
				Expect(err).To(BeNil())

				actualEncKey, err := remoteKeys.ByUse("enc")
				Expect(err).To(BeNil())
				actualSignKey, err := remoteKeys.ByUse("sig")

				Expect(err).To(BeNil())
				Expect(*actualEncKey).To(Equal(expectedKeySet.Keys[1]))
				Expect(*actualSignKey).To(Equal(expectedKeySet.Keys[0]))
			})

			It("refreshes the keys if the keys have expired", func() {
				body := fmt.Sprintf(`{"keys":[%s]}`, signKeyMarshaled)
				numberOfCalls := 0
				mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
					var headers http.Header
					if numberOfCalls == 0 {
						headers = http.Header{
							"Content-Type": {"application/json"},
						}
						numberOfCalls++
					} else {
						headers = http.Header{
							"Content-Type":  {"application/json"},
							"Cache-Control": {"max-age=3600"},
						}
					}
					return newMockResponse(http.StatusOK, headers, body), nil
				})

				var expectedKeySet jose.JSONWebKeySet
				err = json.Unmarshal([]byte(body), &expectedKeySet)
				Expect(err).To(BeNil())

				ctx := context.Background()
				ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
				remoteKeys, err := providerRemoteKeys(ctxWithClient, uri)
				Expect(err).To(BeNil())

				now := time.Now().UTC()
				Expect(remoteKeys.Expiry).Should(BeTemporally("<=", now))

				actualSignKey, err := remoteKeys.ByUse("sig")
				Expect(err).To(BeNil())
				Expect(*actualSignKey).To(Equal(expectedKeySet.Keys[0]))
				Expect(remoteKeys.Expiry).Should(BeTemporally(">=", now.Add(1*time.Hour)))
			})

			It("does not refresh the keys if keys are not expired", func() {
				body := fmt.Sprintf(`{"keys":[%s]}`, signKeyMarshaled)
				numberOfCalls := 0
				mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
					numberOfCalls++
					headers := http.Header{
						"Content-Type":  {"application/json"},
						"Cache-Control": {"max-age=3600"},
					}
					return newMockResponse(http.StatusOK, headers, body), nil
				})

				var expectedKeySet jose.JSONWebKeySet
				err = json.Unmarshal([]byte(body), &expectedKeySet)
				Expect(err).To(BeNil())

				ctx := context.Background()
				ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
				remoteKeys, err := providerRemoteKeys(ctxWithClient, uri)
				Expect(err).To(BeNil())

				now := time.Now().UTC()
				origExpiry := remoteKeys.Expiry

				// First call
				actualSignKey, err := remoteKeys.ByUse("sig")
				Expect(err).To(BeNil())
				Expect(*actualSignKey).To(Equal(expectedKeySet.Keys[0]))
				Expect(remoteKeys.Expiry).Should(BeTemporally(">=", now.Add(59*time.Minute+59*time.Second)))

				// Second call
				actualSignKey, err = remoteKeys.ByUse("sig")
				Expect(err).To(BeNil())
				Expect(remoteKeys.Expiry).Should(Equal(origExpiry))
				Expect(numberOfCalls).To(Equal(1))
			})

			It("returns an error if key cannot be found", func() {
				body := fmt.Sprintf(`{"keys":[%s]}`, signKeyMarshaled)
				mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
					headers := http.Header{
						"Content-Type":  {"application/json"},
						"Cache-Control": {"max-age=3600"},
					}
					return newMockResponse(http.StatusOK, headers, body), nil
				})

				ctx := context.Background()
				ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
				remoteKeys, err := providerRemoteKeys(ctxWithClient, uri)
				Expect(err).To(BeNil())

				actualSignKey, err := remoteKeys.ByUse("enc")
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("key not found"))
				Expect(actualSignKey).To(BeNil())
			})
		})

		Describe("ById", func() {
			It("successfully returns a key by usage from the key store", func() {
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
				Expect(err).To(BeNil())

				ctx := context.Background()
				ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
				remoteKeys, err := providerRemoteKeys(ctxWithClient, uri)
				Expect(err).To(BeNil())

				actualEncKey, err := remoteKeys.ById(encKeyId)
				Expect(err).To(BeNil())
				actualSignKey, err := remoteKeys.ById(signKeyId)

				Expect(err).To(BeNil())
				Expect(*actualEncKey).To(Equal(expectedKeySet.Keys[1]))
				Expect(*actualSignKey).To(Equal(expectedKeySet.Keys[0]))
			})

			It("refreshes the keys if the keys have expired", func() {
				body := fmt.Sprintf(`{"keys":[%s]}`, signKeyMarshaled)
				numberOfCalls := 0
				mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
					var headers http.Header
					if numberOfCalls == 0 {
						headers = http.Header{
							"Content-Type": {"application/json"},
						}
						numberOfCalls++
					} else {
						headers = http.Header{
							"Content-Type":  {"application/json"},
							"Cache-Control": {"max-age=3600"},
						}
					}
					return newMockResponse(http.StatusOK, headers, body), nil
				})

				var expectedKeySet jose.JSONWebKeySet
				err = json.Unmarshal([]byte(body), &expectedKeySet)
				Expect(err).To(BeNil())

				ctx := context.Background()
				ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
				remoteKeys, err := providerRemoteKeys(ctxWithClient, uri)
				Expect(err).To(BeNil())

				now := time.Now().UTC()
				Expect(remoteKeys.Expiry).Should(BeTemporally("<=", now))

				actualSignKey, err := remoteKeys.ById(signKeyId)
				Expect(err).To(BeNil())
				Expect(*actualSignKey).To(Equal(expectedKeySet.Keys[0]))
				Expect(remoteKeys.Expiry).Should(BeTemporally(">=", now.Add(1*time.Hour)))
			})

			It("returns an error if key cannot be found", func() {
				body := fmt.Sprintf(`{"keys":[%s]}`, signKeyMarshaled)
				mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
					headers := http.Header{
						"Content-Type":  {"application/json"},
						"Cache-Control": {"max-age=3600"},
					}
					return newMockResponse(http.StatusOK, headers, body), nil
				})

				ctx := context.Background()
				ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
				remoteKeys, err := providerRemoteKeys(ctxWithClient, uri)
				Expect(err).To(BeNil())

				actualSignKey, err := remoteKeys.ById(generateId())
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("key not found"))
				Expect(actualSignKey).To(BeNil())
			})
		})
	})

	Describe("updateKeys", func() {
		It("updates the keys successfully", func() {
			signKeyId := generateId()
			signKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			signKeyJwk := &jose.JSONWebKey{
				Key:          signKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        signKeyId,
				Algorithm:    "RS256",
				Use:          "sig",
			}
			signKeyJwk.Certificates = nil
			signKeyMarshaled, err := signKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			encKeyId := generateId()
			encKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			encKeyJwk := &jose.JSONWebKey{
				Key:          encKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        encKeyId,
				Algorithm:    "RSA-OAEP",
				Use:          "enc",
			}
			encKeyMarshaled, err := encKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			body := fmt.Sprintf(`{"keys":[%s, %s]}`, signKeyMarshaled, encKeyMarshaled)
			mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				return newMockResponse(http.StatusOK, headers, body), nil
			})

			var expectedKeySet jose.JSONWebKeySet
			err = json.Unmarshal([]byte(body), &expectedKeySet)
			Expect(err).To(BeNil())

			ctx := context.Background()
			ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
			jwks, expiry, err := updateKeys(ctxWithClient, uri)

			now := time.Now().UTC()
			Expect(jwks).To(Equal(expectedKeySet.Keys))
			Expect(expiry).Should(BeTemporally("<=", now))
			Expect(err).To(BeNil())
		})

		It("fails when request cannot be created", func() {
			invalidUri := string([]byte{0x7f})
			jwks, expiry, err := updateKeys(nil, invalidUri)
			invalidCharacter := "\u007f"
			expectedError := fmt.Sprintf("unable to create request: parse %q: net/url: invalid control character in URL", invalidCharacter)
			Expect(jwks).To(BeNil())
			Expect(err).NotTo(BeNil())
			Expect(expiry).To(Equal(time.Time{}))
			Expect(err.Error()).To(Equal(expectedError))
		})

		It("fails when request to uri fails", func() {
			mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
				return &http.Response{}, errors.New("request failed")
			})

			ctx := context.Background()
			ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
			jwks, expiry, err := updateKeys(ctxWithClient, uri)

			expectedError := "unable to fetch keys Get \"https://example.com/oidc/jwks.json\": request failed"
			Expect(jwks).To(BeNil())
			Expect(err).NotTo(BeNil())
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
			jwks, expiry, err := updateKeys(ctxWithClient, uri)

			expectedError := fmt.Sprintf("unable to get keys: %s %s", http.StatusText(http.StatusInternalServerError), body)
			Expect(jwks).To(BeNil())
			Expect(err).NotTo(BeNil())
			Expect(expiry).To(Equal(time.Time{}))
			Expect(err.Error()).To(Equal(expectedError))
		})

		It("fails when response cache headers cannot be parsed", func() {
			signKeyId := generateId()
			signKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			signKeyJwk := &jose.JSONWebKey{
				Key:          signKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        signKeyId,
				Algorithm:    "RS256",
				Use:          "sig",
			}
			signKeyJwk.Certificates = nil
			signKeyMarshaled, err := signKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			encKeyId := generateId()
			encKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			encKeyJwk := &jose.JSONWebKey{
				Key:          encKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        encKeyId,
				Algorithm:    "RSA-OAEP",
				Use:          "enc",
			}
			encKeyMarshaled, err := encKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

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
			jwks, expiry, err := updateKeys(ctxWithClient, uri)

			expectedError := `unable to parse response cache headers: strconv.ParseUint: parsing "INVALID": invalid syntax`
			Expect(jwks).To(BeNil())
			Expect(err).NotTo(BeNil())
			Expect(expiry).To(Equal(time.Time{}))
			Expect(err.Error()).To(Equal(expectedError))
		})

		It("sets the expiration correctly from response cache control headers", func() {
			signKeyId := generateId()
			signKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			signKeyJwk := &jose.JSONWebKey{
				Key:          signKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        signKeyId,
				Algorithm:    "RS256",
				Use:          "sig",
			}
			signKeyJwk.Certificates = nil
			signKeyMarshaled, err := signKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			encKeyId := generateId()
			encKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			encKeyJwk := &jose.JSONWebKey{
				Key:          encKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        encKeyId,
				Algorithm:    "RSA-OAEP",
				Use:          "enc",
			}
			encKeyMarshaled, err := encKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

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
			Expect(err).To(BeNil())

			now := time.Now().UTC()
			ctx := context.Background()
			ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
			jwks, expiry, err := updateKeys(ctxWithClient, uri)

			Expect(jwks).To(Equal(expectedKeySet.Keys))
			Expect(expiry).Should(BeTemporally(">", now))
			Expect(expiry).Should(BeTemporally("<=", now.Add(1*time.Hour+1*time.Second)))
			Expect(err).To(BeNil())
		})
	})
})
