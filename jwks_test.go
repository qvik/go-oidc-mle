package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
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
})

func generateKey(keyId, alg, use string) (*jose.JSONWebKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &jose.JSONWebKey{Key: key, KeyID: keyId, Algorithm: alg, Use: use}, nil
}
