package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/go-jose/go-jose/v3"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("utils tests", func() {

	Describe("statusCodeIs2xx", func() {
		It("correctly detects HTTP 200", func() {
			Expect(statusCodeIs2xx(http.StatusOK)).To(BeTrue())
		})

		It("correctly detects HTTP 226", func() {
			Expect(statusCodeIs2xx(http.StatusIMUsed)).To(BeTrue())
		})

		It("correctly detects HTTP 300", func() {
			Expect(statusCodeIs2xx(http.StatusMultipleChoices)).To(BeFalse())
		})

		It("correctly detects HTTP 103", func() {
			Expect(statusCodeIs2xx(http.StatusEarlyHints)).To(BeFalse())
		})

		It("199 is not 2xx", func() {
			Expect(statusCodeIs2xx(199)).To(BeFalse())
		})
	})

	Describe("mockEncrypter", func() {
		var (
			encrypter         mockEncrypter
			jsonWebEncryption jose.JSONWebEncryption
			options           jose.EncrypterOptions
		)
		BeforeEach(func() {
			extraHeaders := map[jose.HeaderKey]interface{}{
				jose.HeaderContentType:           "testing",
				jose.HeaderKey("myCustomHeader"): "xyz",
				jose.HeaderType:                  "JWE",
			}
			options = jose.EncrypterOptions{
				Compression:  "",
				ExtraHeaders: extraHeaders,
			}
			header := jose.Header{
				KeyID:        "testKeyId",
				JSONWebKey:   nil,
				Algorithm:    "RSA-OAEP",
				Nonce:        "",
				ExtraHeaders: nil,
			}
			jsonWebEncryption = jose.JSONWebEncryption{
				Header: header,
			}
			encrypter = mockEncrypter{
				encryption: jsonWebEncryption,
				opts:       options,
				error:      nil,
			}
		})

		It("Encrypt(payload []byte) works correctly", func() {
			actual, err := encrypter.Encrypt([]byte("lorem ipsum"))
			Expect(err).To(BeNil())
			Expect(actual).To(Equal(&jsonWebEncryption))
		})

		It("Encrypt(payload []byte) works correctly", func() {
			expectedError := errors.New("test error")
			encrypter.error = expectedError
			actual, err := encrypter.Encrypt([]byte("lorem ipsum"))
			Expect(actual).To(BeNil())
			Expect(err).To(Equal(expectedError))
		})

		It("EncryptWithAuthData(payload, add []byte) works correctly", func() {
			actual, err := encrypter.EncryptWithAuthData([]byte("lorem ipsum"), nil)
			Expect(err).To(BeNil())
			Expect(actual).To(Equal(&jsonWebEncryption))
		})

		It("correctly detects HTTP 300", func() {
			expectedError := errors.New("test error")
			encrypter.error = expectedError
			actual, err := encrypter.EncryptWithAuthData([]byte("lorem ipsum"), nil)
			Expect(actual).To(BeNil())
			Expect(err).To(Equal(expectedError))
		})

		It("Options() works correctly", func() {
			Expect(encrypter.Options()).To(Equal(options))
		})

	})

	Describe("newEncrypter", func() {
		var (
			encKeyId  string
			encKey    *rsa.PrivateKey
			encKeyJwk *jose.JSONWebKey
			err       error
		)

		BeforeEach(func() {
			encKeyId = generateId()
			encKey, _ = rsa.GenerateKey(rand.Reader, 2048)
			encKeyJwk = &jose.JSONWebKey{
				Key:          encKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        encKeyId,
				Algorithm:    "RSA-OAEP",
				Use:          "enc",
			}
			_, err = encKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())
		})

		It("correctly creates encrypter", func() {
			expectedOptions := jose.EncrypterOptions{
				Compression:  "",
				ExtraHeaders: nil,
			}
			expectedOptions.WithType("JWE")
			ctx := context.Background()
			enc := jose.ContentEncryption("A256CBC-HS512")
			alg := jose.KeyAlgorithm(encKeyJwk.Algorithm)
			options := jose.EncrypterOptions{
				Compression:  "",
				ExtraHeaders: nil,
			}
			options.WithType("JWE")
			encrypter, err := newEncrypter(ctx, encKeyJwk, enc, alg, options)
			Expect(err).To(BeNil())
			Expect(encrypter.Options().Compression).To(Equal(expectedOptions.Compression))
			Expect(encrypter.Options().ExtraHeaders).To(Equal(expectedOptions.ExtraHeaders))
		})

		It("uses the encrypter in context if one is present", func() {
			extraHeaders := map[jose.HeaderKey]interface{}{
				jose.HeaderContentType:           "foo/bar",
				jose.HeaderKey("myCustomHeader"): "xyz",
			}
			expectedOptions := jose.EncrypterOptions{
				Compression:  "",
				ExtraHeaders: extraHeaders,
			}
			expectedOptions.WithType("JWE")
			mock := mockEncrypter{
				encryption: jose.JSONWebEncryption{},
				opts:       expectedOptions,
				error:      nil,
			}
			ctx := context.Background()
			ctxWithEncrypter := context.WithValue(ctx, EncrypterContextKey, mock)
			enc := jose.ContentEncryption("A256CBC-HS512")
			alg := jose.KeyAlgorithm(encKeyJwk.Algorithm)
			options := jose.EncrypterOptions{
				Compression:  "",
				ExtraHeaders: nil,
			}
			options.WithType("JWE")
			encrypter, err := newEncrypter(ctxWithEncrypter, encKeyJwk, enc, alg, options)
			Expect(err).To(BeNil())
			Expect(encrypter.Options().Compression).To(Equal(expectedOptions.Compression))
			Expect(encrypter.Options().ExtraHeaders).To(Equal(expectedOptions.ExtraHeaders))
		})

		It("fails to create encrypter if the key is invalid", func() {
			encKeyJwk.Algorithm = "INVALID"
			ctx := context.Background()
			enc := jose.ContentEncryption("A256CBC-HS512")
			alg := jose.KeyAlgorithm(encKeyJwk.Algorithm)
			options := jose.EncrypterOptions{
				Compression:  "",
				ExtraHeaders: nil,
			}
			options.WithType("JWE")
			_, err := newEncrypter(ctx, encKeyJwk, enc, alg, options)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("go-jose/go-jose: unknown/unsupported algorithm"))
		})
	})

	Describe("addOpenIdToScope", func() {
		It("adds openid to scope if not present", func() {
			input := []string{"one", "two", "three"}
			expected := append([]string{"openid"}, input...)
			Expect(addOpenIdToScope(input)).To(Equal(expected))
		})

		It("doesn't add openid if already specified in the scope", func() {
			input := []string{"one", "two", "openid", "three"}
			Expect(addOpenIdToScope(input)).To(Equal(input))
		})
	})
})
