package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gopkg.in/square/go-jose.v2"
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

		It("correctly creates encrypted", func() {
			expectedOptions := jose.EncrypterOptions{
				Compression:  "",
				ExtraHeaders: nil,
			}
			expectedOptions.WithType("JWE")
			encrypter, err := newEncrypter(encKeyJwk)
			Expect(err).To(BeNil())
			Expect(encrypter.Options().Compression).To(Equal(expectedOptions.Compression))
			Expect(encrypter.Options().ExtraHeaders).To(Equal(expectedOptions.ExtraHeaders))
		})

		It("fails to create encrypter if the key is invalid", func() {
			encKeyJwk.Algorithm = "INVALID"
			_, err := newEncrypter(encKeyJwk)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("square/go-jose: unknown/unsupported algorithm"))
		})
	})
})
