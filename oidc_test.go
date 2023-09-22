package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type MockRoundTrip func(request *http.Request) (*http.Response, error)

func (m MockRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return m(request)
}

func newMockClient(fn MockRoundTrip) *http.Client {
	return &http.Client{
		Transport: fn,
	}
}

func newMockResponse(statusCode int, headers http.Header, body string) *http.Response {
	b := bytes.NewBufferString(body)
	mockBody := io.NopCloser(b)
	return &http.Response{
		Status:        http.StatusText(statusCode),
		StatusCode:    statusCode,
		Header:        headers,
		Body:          mockBody,
		ContentLength: int64(b.Len()),
	}
}

type user struct {
	Subject    string `json:"sub"`
	Name       string `json:"name"`
	SSN        string `json:"signicat.national_id"`
	GivenName  string `json:"given_name"`
	Locale     string `json:"locale"`
	FamilyName string `json:"family_name"`
}

type jwtClaims struct {
	Issuer    string           `json:"iss,omitempty"`
	Subject   string           `json:"sub,omitempty"`
	Audience  jwt.Audience     `json:"aud,omitempty"`
	Expiry    *jwt.NumericDate `json:"exp,omitempty"`
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *jwt.NumericDate `json:"iat,omitempty"`
	ID        string           `json:"jti,omitempty"`
	Nonce     string           `json:"nonce,omitempty"`
}

// This is the openid configuration that is used in unit tests.
const openidConfiguration = `{
	"issuer":"https://example.com/oidc",
	"authorization_endpoint":"https://example.com/oidc/authorize",
	"token_endpoint":"https://example.com/oidc/token",
	"userinfo_endpoint":"https://example.com/oidc/userinfo",
	"jwks_uri":"https://example.com/oidc/jwks.json",
	"scopes_supported":["openid","profile","email","address","phone","offline_access"],
	"response_types_supported":["code"],
	"response_modes_supported":["query"],
	"grant_types_supported":["authorization_code","refresh_token","client_credentials"],
	"subject_types_supported":["pairwise"],
	"id_token_signing_alg_values_supported":["RS256"],
	"id_token_encryption_alg_values_supported":["RSA1_5","RSA-OAEP","dir","A128KW","A256KW","ECDH-ES"],
	"id_token_encryption_enc_values_supported":["A128CBC-HS256"],
	"userinfo_signing_alg_values_supported":["RS256"],
	"userinfo_encryption_alg_values_supported":["RSA1_5","RSA-OAEP","dir","A128KW","A256KW","ECDH-ES"],
	"userinfo_encryption_enc_values_supported":["A128CBC-HS256"],
	"request_object_signing_alg_values_supported":["RS256"],
	"request_object_encryption_alg_values_supported":["RSA-OAEP"],
	"request_object_encryption_enc_values_supported":["A128CBC-HS256","A256CBC-HS512","A128GCM","A256GCM"],
	"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt"],
	"claim_types_supported":["normal","aggregated"],
	"claims_supported":["sub","name","family_name","given_name","middle_name","nickname","preferred_username","profile","picture","website","gender","birthdate","zoneinfo","locale","updated_at","email","email_verified","phone_number","phone_number_verified","address","address.formatted","address.street_address","address.locality","address.region","address.postal_code","address.country"],
	"service_documentation":"https://developer.example.com/",
	"claims_parameter_supported":true,
	"request_parameter_supported":true,
	"request_uri_parameter_supported":false,
	"require_request_uri_registration":true,
	"op_policy_uri":"https://www.example.com/privacy-and-cookies/",
	"check_session_iframe":"https://example.com/oidc/session/check",
	"end_session_endpoint":"https://example.com/oidc/session/end",
	"backchannel_logout_supported":true,
	"backchannel_logout_session_supported":false
}`

// remoteJwks describes the service provider's public keys for signing and encryption.
const remoteJwks = `{
	"keys":[
		{
			"kty":"RSA",
			"e":"AQAB",
			"use":"sig",
			"kid":"any.oidc-signature-preprod.test.jwk.v.1",
			"alg":"RS256",
			"n":"px6mGAGqVTcf8SNBzGF5ZzMQem8QH2wXO1xXEgwQAsBCcVvlpliIj1gkPDux36DYAgdUYy1wM7VhW6FHNhT1yCA7aYteUKB9hKAai3wzQNoUXPHQlKQsWRgTboFRQrkKzPgHHIp8IwZxBFzjCp9W9gdQ_LIQyCyjxoRTR0yg21HB1SC2bh91L2K689IpS9qcb7KBjizVmGqwRCgWtA1lBOKEpgrhPeHnSLcvRWG97ePR5MfmzftWxRftWIlDaIWV_3cnn8WsXH2Qtg4cq5FGBdS30SWHTpYNRuLYfvttivR1uZmx8fnnYEfy3L7lxHbWuVbdkySofQ7yvJWX56GGJw"
		}
		,{
			"kty":"RSA",
			"e":"AQAB",
			"use":"enc",
			"kid":"any.oidc-encryption-preprod.test.jwk.v.1",
			"alg":"RSA-OAEP",
			"n":"ou9ZQ_e0JSMhOA3fSwzH4h9OHgS8xLbtScHUlQEq9XWRw0i5ZefGWEUCeWJgehxuRMumPdm5_csfSnJLJom3c5cEnloXB53ZFEa6qJ7AEHnSjdMxnIkzcq_4ICQg69fwTac1ZCjxhCraUs6G9LE8b9gN-EHmd8MXuLRxZUkjlgiQKb-XhfDaDA7rd7KMczyxrieZT3q5lk1fjw2V_o_jasowLo8i7s8Wa4S7BAg1ZFv2-oc8PcobbJLsAAIxg3PEn0nDIvNcs6cjjYje2_TrrXMmis2TJquQhLOHjx_yQdzQNfzxC5_GwOZPBKZR1gH1-QxlW7q8jevC2-f_-7FlHw"
		}
	]
}`

// remoteEncKey is the provided as a separate constant to avoid unnecessary repetition.
const remoteEncKey = `{
	"kty":"RSA",
	"e":"AQAB",
	"use":"enc",
	"kid":"any.oidc-encryption-preprod.test.jwk.v.1",
	"alg":"RSA-OAEP",
	"n":"ou9ZQ_e0JSMhOA3fSwzH4h9OHgS8xLbtScHUlQEq9XWRw0i5ZefGWEUCeWJgehxuRMumPdm5_csfSnJLJom3c5cEnloXB53ZFEa6qJ7AEHnSjdMxnIkzcq_4ICQg69fwTac1ZCjxhCraUs6G9LE8b9gN-EHmd8MXuLRxZUkjlgiQKb-XhfDaDA7rd7KMczyxrieZT3q5lk1fjw2V_o_jasowLo8i7s8Wa4S7BAg1ZFv2-oc8PcobbJLsAAIxg3PEn0nDIvNcs6cjjYje2_TrrXMmis2TJquQhLOHjx_yQdzQNfzxC5_GwOZPBKZR1gH1-QxlW7q8jevC2-f_-7FlHw"
}`

var _ = Describe("Must tests", func() {
	It("does not panic if error == nil", func() {
		Expect(func() {
			Must(&OIDCClient{}, nil)
		}).NotTo(Panic())
	})

	It("panics if error is not returned", func() {
		Expect(func() {
			Must(nil, errors.New("oh noes"))
		}).To(Panic())
	})
})

var _ = Describe("OIDCClient tests", func() {
	var (
		mockClient *http.Client
		config     Config
	)

	BeforeEach(func() {
		config = Config{
			ClientId:     "exampleClientId",
			ClientSecret: "exampleClientSecret",
			Endpoint:     "https://example.com/oidc",
			RedirectUri:  "http://localhost:5000/redirect",
			Scopes:       []string{"profile", "signicat.national_id"},
		}

		mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
			headers := http.Header{
				"Content-Type": {"application/json"},
			}
			if req.URL.Path == "/oidc/.well-known/openid-configuration" {
				return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
			} else if req.URL.Path == "/oidc/jwks.json" {
				return newMockResponse(http.StatusOK, headers, remoteJwks), nil
			} else {
				body := `{"error":"invalid path"}`
				return newMockResponse(http.StatusInternalServerError, headers, body), nil
			}
		})
	})

	Describe("Initialization", func() {
		It("initializes client successfully", func() {
			ctx := context.Background()
			client, err := NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)

			Expect(err).To(BeNil())
			Expect(client.provider.Endpoint().AuthURL).To(Equal("https://example.com/oidc/authorize"))
			Expect(client.provider.Endpoint().TokenURL).To(Equal("https://example.com/oidc/token"))
			Expect(client.config.ClientId).To(Equal(config.ClientId))
			Expect(client.config.ClientSecret).To(Equal(config.ClientSecret))
			Expect(client.config.Endpoint).To(Equal(config.Endpoint))
			Expect(client.config.RedirectUri).To(Equal(config.RedirectUri))
			Expect(client.config.Scopes).To(Equal(config.Scopes))
		})

		It("fails to initialize client if discovery fails", func() {
			body := `{"error":"Internal Server Error"}`
			mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				return newMockResponse(http.StatusInternalServerError, headers, body), nil
			})

			ctx := context.Background()
			client, err := NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)

			Expect(err).NotTo(BeNil())
			Expect(client).To(BeNil())
			Expect(err.Error()).To(Equal(fmt.Sprintf("unable to initialize client: %s: %s", http.StatusText(http.StatusInternalServerError), body)))
		})
	})

	Describe("AuthRequestURL", func() {
		It("returns authorization request url with correct parameters", func() {
			state := generateId()
			options := map[string]interface{}{
				"acr_values": "urn:signicat:oidc:method:ftn-op-auth",
				"ui_locales": "fi",
			}
			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			authUrl, err := client.AuthRequestURL(state, options)
			Expect(err).To(BeNil())

			parsedUrl, err := url.Parse(authUrl)
			Expect(err).To(BeNil())

			Expect(parsedUrl.Query().Get("redirect_uri")).To(Equal(config.RedirectUri))
			Expect(parsedUrl.Query().Get("state")).To(Equal(state))
			Expect(parsedUrl.Query().Get("response_type")).To(Equal("code"))
			Expect(parsedUrl.Query().Get("scope")).To(Equal(strings.Join(config.Scopes, " ")))
			Expect(parsedUrl.Query().Get("acr_values")).To(Equal(options["acr_values"]))
			Expect(parsedUrl.Query().Get("ui_locales")).To(Equal(options["ui_locales"]))
			Expect(parsedUrl.Query().Get("client_id")).To(Equal(config.ClientId))
			Expect(parsedUrl.Path).To(Equal("/oidc/authorize"))
		})

		It("returns authorization request url with complex parameters", func() {
			state := generateId()
			options := map[string]interface{}{
				"acr_values":  "urn:signicat:oidc:method:ftn-op-auth",
				"ui_locales":  "fi",
				"login_hints": []string{"birthday-121212", "phoneno-nnnnnnnn"},
			}
			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			authUrl, err := client.AuthRequestURL(state, options)
			Expect(err).To(BeNil())

			parsedUrl, err := url.Parse(authUrl)
			Expect(err).To(BeNil())

			Expect(parsedUrl.Query().Get("redirect_uri")).To(Equal(config.RedirectUri))
			Expect(parsedUrl.Query().Get("state")).To(Equal(state))
			Expect(parsedUrl.Query().Get("response_type")).To(Equal("code"))
			Expect(parsedUrl.Query().Get("scope")).To(Equal(strings.Join(config.Scopes, " ")))
			Expect(parsedUrl.Query().Get("acr_values")).To(Equal(options["acr_values"]))
			Expect(parsedUrl.Query().Get("ui_locales")).To(Equal(options["ui_locales"]))
			Expect(parsedUrl.Query().Get("client_id")).To(Equal(config.ClientId))
			Expect(parsedUrl.Path).To(Equal("/oidc/authorize"))
		})
	})

	Describe("Exchange", func() {
		BeforeEach(func() {
			config = Config{
				ClientId:     "demo-preprod", // Must be demo-preprod or else the token verification will fail as the token audience does not contain the correct client id
				ClientSecret: "exampleClientSecret",
				Endpoint:     "https://example.com/oidc",
				RedirectUri:  "http://localhost:5000/redirect",
				Scopes:       []string{"profile", "signicat.national_id"},
			}

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				path := req.URL.Path
				if path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if path == "/oidc/token" {
					body := `{
						"access_token":"eyJraWQiOiJhbnkub2lkYy1zaWduYXR1cmUtcHJlcHJvZC50ZXN0Lmp3ay52LjEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiItWC1RLTFnbUktSWxSLXpoOGdkc0NOZ0FqUlowWmpYOSIsInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIl0sInNubSI6ImRlbW8iLCJpc3MiOiJodHRwczpcL1wvcHJlcHJvZC5zaWduaWNhdC5jb21cL29pZGMiLCJleHAiOjE1NzA3MTc1NTEsImlhdCI6MTU3MDcxNTc1MSwianRpIjoiRnlzVkVPaENURzJUSjg0ZWxIZDVOTDZkNVhtWUp2OC0iLCJjaWQiOiJkZW1vLXByZXByb2QifQ.Lm8pqn0F3euTOttBz3VEryIz-VoeBAABDxjhcCC3hMqa5-nl5SJIg7xIoCQ8hSsqcRmxPRSF6gbyKJU52TwH3miVVYoemBzVL0cqxwDXxBc5oZhUSEr3CkVME34URd-q9ThQugJXWzSrrvxtgdbklb_eEijF1BuZc0zOMtsLXdV88foy-p6PeGQ7EhRpsoa_DEB88zzE5AGpStG4PLotYs0ev3E5sLgViAsqAKrPV26V2gHpdEnYFqAJz6AoSA7LntM_9im1TF3VnLRt467-2a8qYPuDcsnjudjajElmAYEZ9qQ6B0cUtNJV-dU8aDF1vJ7GpgolY05psUJVXcbNAg",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":1800,
						"id_token":"eyJraWQiOiJhbnkub2lkYy1zaWduYXR1cmUtcHJlcHJvZC50ZXN0Lmp3ay52LjEiLCJhbGciOiJSUzI1NiJ9.eyJhY3IiOiJ1cm46c2lnbmljYXQ6b2lkYzptZXRob2Q6aWRpbiIsInN1YiI6Ii1YLVEtMWdtSS1JbFItemg4Z2RzQ05nQWpSWjBaalg5IiwiYXVkIjoiZGVtby1wcmVwcm9kIiwibmJmIjoxNTcwNzE1NzUxLCJhdXRoX3RpbWUiOjE1NzA3MTU3NDAsImFtciI6InVybjprc2k6bmFtZXM6U0FNTDoyLjA6YWM6aURJTiIsImlzcyI6Imh0dHBzOlwvXC9wcmVwcm9kLnNpZ25pY2F0LmNvbVwvb2lkYyIsImV4cCI6MTU3MDcxOTM1MSwiaWF0IjoxNTcwNzE1NzUxfQ.T9h62zn_IWGu4s9yyW0sf7HmGW2zLZajTF56l-_xDTG_tyTAryuKW9O6fixLkZoz8Mfh-AKBSqPt5bj8Z642mmVNaFZLhrvjtTyO_xvQc448BBKmVu7doPH4fBAFeA8IX-kUGEPN6djH3gLC75UifxG_URkHTqJSCpZXVNIjAy5g7m2_DISm4n3-uijWMMnwQoGPn1FvM2agwNIuMPLuGmmF5-YLGs8T7_9AasSUlYhMpjiATkolcajrXSMAizCKreRldxXK8dLwlh0UyFcosaHyVr0hiAa3LRV9i4crcfyKsh-NfFw6eSvZfmMA-UWt-jlSpB2g8mQIqPxJbbr8Xg"
					}`
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if path == "/oidc/jwks.json" {
					return newMockResponse(http.StatusOK, headers, remoteJwks), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})
		})

		It("successfully exchanges authorization code for token", func() {
			keyId := generateId()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: keyId, Algorithm: "RS256", Use: "sig"}
			keyJWKSMarshaled, err := keyJWK.MarshalJSON()

			now := time.Now().UTC()
			in10mins := time.Now().UTC().Add(10 * time.Minute)
			idTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  []string{"demo-preprod"},
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
			}

			accessTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  []string{"demo-preprod"},
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
			}

			idToken, err := buildSignedJWTToken(key, keyId, idTokenClaims)
			Expect(err).To(BeNil())
			accessToken, err := buildSignedJWTToken(key, keyId, accessTokenClaims)
			Expect(err).To(BeNil())

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, idToken)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, keyJWKSMarshaled, remoteEncKey)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
			options := map[string]string{
				"client_id": "exampleClientId",
			}

			code := generateId()
			oauth2Token, err := client.Exchange(code, options)
			Expect(err).To(BeNil())
			Expect(oauth2Token).NotTo(BeNil())
		})

		It("fails when signature is invalid", func() {
			ctx := context.Background()
			code := generateId()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
			options := map[string]string{
				"client_id": "exampleClientId",
			}

			oauth2Token, err := client.Exchange(code, options)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("unable to verify signature"))
			Expect(oauth2Token).To(BeNil())
		})

		It("fails when oauth2 token does not contain id_token", func() {
			keyId := generateId()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: keyId, Algorithm: "RS256", Use: "sig"}
			keyJWKSMarshaled, err := keyJWK.MarshalJSON()
			Expect(err).To(BeNil())

			in10mins := time.Now().UTC().Add(10 * time.Minute)
			accessTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  []string{"demo-preprod"},
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(time.Now().UTC()),
				IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
				ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
			}

			accessToken, err := buildSignedJWTToken(key, keyId, accessTokenClaims)
			Expect(err).To(BeNil())

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600
					}`, accessToken)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, keyJWKSMarshaled, remoteEncKey)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
			options := map[string]string{
				"client_id": "exampleClientId",
			}

			code := generateId()
			oauth2Token, err := client.Exchange(code, options)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("no id_token field in oauth2 token"))
			Expect(oauth2Token).To(BeNil())
		})

		It("fails when code cannot be exchanged to oauth2 token", func() {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: "test key id", Algorithm: "RS256", Use: "sig"}
			keyJWKSMarshaled, err := keyJWK.MarshalJSON()
			Expect(err).To(BeNil())

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := `{"error":"bad request"}`
					return newMockResponse(http.StatusBadRequest, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, keyJWKSMarshaled, remoteEncKey)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
			options := map[string]string{
				"client_id": "exampleClientId",
			}

			code := generateId()
			oauth2Token, err := client.Exchange(code, options)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("unable to exchange code for token"))
			Expect(oauth2Token).To(BeNil())
		})
	})

	Describe("ExchangeWithNonce", func() {
		It("correctly exchanges authorization code for token and validates the nonce", func() {
			config = Config{
				ClientId:     "exampleClientId",
				ClientSecret: "exampleClientSecret",
				Endpoint:     "https://example.com/oidc",
				RedirectUri:  "http://localhost:5000/redirect",
				Scopes:       []string{"profile", "signicat.national_id"},
			}

			keyId := generateId()
			key, _ := rsa.GenerateKey(rand.Reader, 2048)
			keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: keyId, Algorithm: "RS256", Use: "sig"}
			keyJWKSMarshaled, err := keyJWK.MarshalJSON()

			now := time.Now().UTC()
			in10mins := time.Now().UTC().Add(10 * time.Minute)
			audience := []string{config.ClientId}
			nonce := generateId()
			idTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  audience,
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				Nonce:     nonce,
			}

			accessTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  audience,
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
			}

			idToken, err := buildSignedJWTToken(key, keyId, idTokenClaims)
			Expect(err).To(BeNil())
			accessToken, err := buildSignedJWTToken(key, keyId, accessTokenClaims)
			Expect(err).To(BeNil())

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, idToken)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, keyJWKSMarshaled, remoteEncKey)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
			options := map[string]string{
				"client_id": "exampleClientId",
			}
			state := generateId()
			tokens, err := client.ExchangeWithNonce(state, nonce, options)
			Expect(err).To(BeNil())
			Expect(tokens.Oauth2Token.Expiry.Unix()).To(Equal(accessTokenClaims.Expiry.Time().Unix()))
			Expect(tokens.Oauth2Token.TokenType).To(Equal("Bearer"))
			Expect(tokens.Oauth2Token.RefreshToken).To(Equal("4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4"))
			Expect(tokens.Oauth2Token.AccessToken).To(Equal(accessToken))

			Expect(tokens.IdToken.Expiry.Unix()).To(Equal(in10mins.Unix()))
			Expect(tokens.IdToken.Nonce).To(Equal(idTokenClaims.Nonce))
			Expect(tokens.IdToken.Subject).To(Equal(idTokenClaims.Subject))
			Expect(tokens.IdToken.Audience).To(Equal(audience))
			Expect(tokens.IdToken.IssuedAt).To(Equal(idTokenClaims.IssuedAt.Time()))
			Expect(tokens.IdToken.Issuer).To(Equal(idTokenClaims.Issuer))
		})

		It("fails when provider's token endpoint fails", func() {
			config = Config{
				ClientId:     "exampleClientId",
				ClientSecret: "exampleClientSecret",
				Endpoint:     "https://example.com/oidc",
				RedirectUri:  "http://localhost:5000/redirect",
				Scopes:       []string{"profile", "signicat.national_id"},
			}

			keyId := generateId()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: keyId, Algorithm: "RS256", Use: "sig"}
			keyJWKSMarshaled, err := keyJWK.MarshalJSON()
			nonce := generateId()

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := `{"error": "internal server error"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, keyJWKSMarshaled, remoteEncKey)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
			options := map[string]string{
				"client_id": "exampleClientId",
			}
			state := generateId()
			tokens, err := client.ExchangeWithNonce(state, nonce, options)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("unable to exchange code for token"))
			Expect(tokens).To(BeNil())
		})
	})

	Describe("UserInfo", func() {
		BeforeEach(func() {
			config = Config{
				ClientId:     "demo-preprod",
				ClientSecret: "exampleClientSecret",
				Endpoint:     "https://example.com/oidc",
				RedirectUri:  "http://localhost:5000/redirect",
				Scopes:       []string{"profile", "signicat.national_id"},
			}

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				path := req.URL.Path
				if path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if path == "/oidc/token" {
					body := `{
						"access_token":"eyJraWQiOiJhbnkub2lkYy1zaWduYXR1cmUtcHJlcHJvZC50ZXN0Lmp3ay52LjEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiItWC1RLTFnbUktSWxSLXpoOGdkc0NOZ0FqUlowWmpYOSIsInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIl0sInNubSI6ImRlbW8iLCJpc3MiOiJodHRwczpcL1wvcHJlcHJvZC5zaWduaWNhdC5jb21cL29pZGMiLCJleHAiOjE1NzA3MTc1NTEsImlhdCI6MTU3MDcxNTc1MSwianRpIjoiRnlzVkVPaENURzJUSjg0ZWxIZDVOTDZkNVhtWUp2OC0iLCJjaWQiOiJkZW1vLXByZXByb2QifQ.Lm8pqn0F3euTOttBz3VEryIz-VoeBAABDxjhcCC3hMqa5-nl5SJIg7xIoCQ8hSsqcRmxPRSF6gbyKJU52TwH3miVVYoemBzVL0cqxwDXxBc5oZhUSEr3CkVME34URd-q9ThQugJXWzSrrvxtgdbklb_eEijF1BuZc0zOMtsLXdV88foy-p6PeGQ7EhRpsoa_DEB88zzE5AGpStG4PLotYs0ev3E5sLgViAsqAKrPV26V2gHpdEnYFqAJz6AoSA7LntM_9im1TF3VnLRt467-2a8qYPuDcsnjudjajElmAYEZ9qQ6B0cUtNJV-dU8aDF1vJ7GpgolY05psUJVXcbNAg",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":1800,
						"id_token":"eyJraWQiOiJhbnkub2lkYy1zaWduYXR1cmUtcHJlcHJvZC50ZXN0Lmp3ay52LjEiLCJhbGciOiJSUzI1NiJ9.eyJhY3IiOiJ1cm46c2lnbmljYXQ6b2lkYzptZXRob2Q6aWRpbiIsInN1YiI6Ii1YLVEtMWdtSS1JbFItemg4Z2RzQ05nQWpSWjBaalg5IiwiYXVkIjoiZGVtby1wcmVwcm9kIiwibmJmIjoxNTcwNzE1NzUxLCJhdXRoX3RpbWUiOjE1NzA3MTU3NDAsImFtciI6InVybjprc2k6bmFtZXM6U0FNTDoyLjA6YWM6aURJTiIsImlzcyI6Imh0dHBzOlwvXC9wcmVwcm9kLnNpZ25pY2F0LmNvbVwvb2lkYyIsImV4cCI6MTU3MDcxOTM1MSwiaWF0IjoxNTcwNzE1NzUxfQ.T9h62zn_IWGu4s9yyW0sf7HmGW2zLZajTF56l-_xDTG_tyTAryuKW9O6fixLkZoz8Mfh-AKBSqPt5bj8Z642mmVNaFZLhrvjtTyO_xvQc448BBKmVu7doPH4fBAFeA8IX-kUGEPN6djH3gLC75UifxG_URkHTqJSCpZXVNIjAy5g7m2_DISm4n3-uijWMMnwQoGPn1FvM2agwNIuMPLuGmmF5-YLGs8T7_9AasSUlYhMpjiATkolcajrXSMAizCKreRldxXK8dLwlh0UyFcosaHyVr0hiAa3LRV9i4crcfyKsh-NfFw6eSvZfmMA-UWt-jlSpB2g8mQIqPxJbbr8Xg"
					}`
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if path == "/oidc/jwks.json" {
					return newMockResponse(http.StatusOK, headers, remoteJwks), nil
				} else if path == "/oidc/userinfo" {
					body := `{
					   "sub":"IY1kAqvxOLMOZBDGuMpG6lcTAi_qJihr",
					   "name":"Väinö Tunnistus",
					   "given_name":"Väinö",
					   "locale":"FI",
						"signicat.national_id": "123456-123A",
					   "ftn.idpId":"fi-op",
					   "family_name":"Tunnistus"
					}`
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})
		})

		It("successfully fetches the user info", func() {
			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			var userInfo user
			oauth2Token := oauth2.Token{}
			err := client.UserInfo(oauth2.StaticTokenSource(&oauth2Token), &userInfo)
			Expect(err).To(BeNil())
			Expect(userInfo.Name).To(Equal("Väinö Tunnistus"))
			Expect(userInfo.Subject).To(Equal("IY1kAqvxOLMOZBDGuMpG6lcTAi_qJihr"))
			Expect(userInfo.GivenName).To(Equal("Väinö"))
			Expect(userInfo.Locale).To(Equal("FI"))
			Expect(userInfo.FamilyName).To(Equal("Tunnistus"))
		})

		It("fails when userinfo endpoint fails to return user info", func() {
			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				path := req.URL.Path
				if path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if path == "/oidc/jwks.json" {
					return newMockResponse(http.StatusOK, headers, remoteJwks), nil
				} else if path == "/oidc/userinfo" {
					body := `{"error": "internal server error"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			ctx := context.Background()
			oauth2Token := oauth2.Token{}
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			var userInfo user
			err := client.UserInfo(oauth2.StaticTokenSource(&oauth2Token), &userInfo)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal(`unable to fetch user info: Internal Server Error: {"error": "internal server error"}`))
		})
	})

	Describe("HandleCallback", func() {
		BeforeEach(func() {
			config = Config{
				ClientId:     "exampleClientId",
				ClientSecret: "exampleClientSecret",
				Endpoint:     "https://example.com/oidc",
				RedirectUri:  "http://localhost:5000/redirect",
				Scopes:       []string{"profile", "signicat.national_id"},
			}
		})

		It("successfully handles the callback", func() {
			keyId := generateId()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: keyId, Algorithm: "RS256", Use: "sig"}
			keyJWKSMarshaled, err := keyJWK.MarshalJSON()

			now := time.Now().UTC()
			in10mins := time.Now().UTC().Add(10 * time.Minute)
			nonce := generateId()
			idTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  []string{"exampleClientId"},
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				Nonce:     nonce,
			}

			accessTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  []string{"exampleClientId"},
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
			}

			idToken, err := buildSignedJWTToken(key, keyId, idTokenClaims)
			Expect(err).To(BeNil())
			accessToken, err := buildSignedJWTToken(key, keyId, accessTokenClaims)
			Expect(err).To(BeNil())

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, idToken)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, keyJWKSMarshaled, remoteEncKey)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/userinfo" {
					body := `{
						"sub":"IY1kAqvxOLMOZBDGuMpG6lcTAi_qJihr",
						"name":"Väinö Tunnistus",
						"given_name":"Väinö",
						"locale":"FI",
						"signicat.national_id": "123456-123A",
						"ftn.idpId":"fi-op",
						"family_name":"Tunnistus"
					}`
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			var userInfo user
			code := generateId()
			state := generateId()
			queryParams := url.Values{
				"code":  {code},
				"state": {state},
			}
			err = client.HandleCallback(state, nonce, queryParams, &userInfo)
			Expect(err).To(BeNil())
			Expect(userInfo.Name).To(Equal("Väinö Tunnistus"))
			Expect(userInfo.Subject).To(Equal("IY1kAqvxOLMOZBDGuMpG6lcTAi_qJihr"))
			Expect(userInfo.GivenName).To(Equal("Väinö"))
			Expect(userInfo.Locale).To(Equal("FI"))
			Expect(userInfo.FamilyName).To(Equal("Tunnistus"))
		})

		It("fails if nonce does not match the one defined in authorization request", func() {
			keyId := generateId()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: keyId, Algorithm: "RS256", Use: "sig"}
			keyJWKSMarshaled, err := keyJWK.MarshalJSON()

			now := time.Now().UTC()
			in10mins := time.Now().UTC().Add(10 * time.Minute)
			nonMatchingNonce := generateId()
			idTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  []string{"exampleClientId"},
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				Nonce:     nonMatchingNonce,
			}

			accessTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  []string{"exampleClientId"},
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
			}

			idToken, err := buildSignedJWTToken(key, keyId, idTokenClaims)
			Expect(err).To(BeNil())
			accessToken, err := buildSignedJWTToken(key, keyId, accessTokenClaims)
			Expect(err).To(BeNil())

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, idToken)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, keyJWKSMarshaled, remoteEncKey)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			var userInfo user
			code := generateId()
			state := generateId()
			nonce := generateId()
			queryParams := url.Values{
				"code":  {code},
				"state": {state},
			}
			err = client.HandleCallback(state, nonce, queryParams, &userInfo)
			Expect(userInfo).To(Equal(user{}))
			Expect(err).NotTo(BeNil())
			expectedErr := fmt.Sprintf("nonce is not the one specified. expected '%s', got '%s'", nonce, nonMatchingNonce)
			Expect(err.Error()).To(Equal(expectedErr))
		})

		It("fails when userinfo endpoint fails to return user info", func() {
			keyId := generateId()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: keyId, Algorithm: "RS256", Use: "sig"}
			keyJWKSMarshaled, err := keyJWK.MarshalJSON()

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := `{"error": "internal server error"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, keyJWKSMarshaled, remoteEncKey)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/userinfo" {
					body := `{
						"sub":"IY1kAqvxOLMOZBDGuMpG6lcTAi_qJihr",
						"name":"Väinö Tunnistus",
						"given_name":"Väinö",
						"locale":"FI",
						"signicat.national_id": "123456-123A",
						"ftn.idpId":"fi-op",
						"family_name":"Tunnistus"
					}`
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})
			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			code := generateId()
			var userInfo user
			state := generateId()
			queryParams := url.Values{
				"code":  {code},
				"state": {state},
			}
			err = client.HandleCallback(state, "", queryParams, userInfo)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("unable to exchange code for token"))
		})

		It("fails when query params contain error parameter", func() {
			keyId := generateId()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: keyId, Algorithm: "RS256", Use: "sig"}
			keyJWKSMarshaled, err := keyJWK.MarshalJSON()

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, keyJWKSMarshaled, remoteEncKey)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})
			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			var userInfo user
			state := generateId()
			authErr := "process failed"
			authErrDesc := "user cancelled the authorization process"
			queryParams := url.Values{
				"error":             {authErr},
				"error_description": {authErrDesc},
				"state":             {state},
			}
			expectedError := fmt.Sprintf("authorization failed. error: %s, description: %s", authErr, authErrDesc)
			err = client.HandleCallback(state, "", queryParams, userInfo)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal(expectedError))
		})

		It("fails when the state does not match", func() {
			keyId := generateId()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: keyId, Algorithm: "RS256", Use: "sig"}
			keyJWKSMarshaled, err := keyJWK.MarshalJSON()

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, keyJWKSMarshaled, remoteEncKey)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})
			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			var userInfo user
			state := generateId()
			state2 := generateId()
			code := generateId()
			queryParams := url.Values{
				"code":  {code},
				"state": {state},
			}
			expectedError := "received state does not match the defined state"
			err = client.HandleCallback(state2, "", queryParams, userInfo)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal(expectedError))
		})

		It("fails when authorization code is missing", func() {
			keyId := generateId()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: keyId, Algorithm: "RS256", Use: "sig"}
			keyJWKSMarshaled, err := keyJWK.MarshalJSON()

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, keyJWKSMarshaled, remoteEncKey)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})
			ctx := context.Background()
			client := Must(NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			var userInfo user
			state := generateId()
			queryParams := url.Values{
				"state": {state},
			}
			expectedError := "authorization code missing"
			err = client.HandleCallback(state, "", queryParams, userInfo)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal(expectedError))
		})
	})
})

var _ = Describe("OIDCClientEncrypted tests", func() {
	var (
		mockClient *http.Client
		config     Config
	)

	Describe("Client initialization", func() {
		BeforeEach(func() {
			config = Config{
				ClientId:     "exampleClientId",
				ClientSecret: "exampleClientSecret",
				Endpoint:     "https://example.com/oidc",
				RedirectUri:  "https://example.com/redirect",
				LocalJWK:     `{ "d": "Na7lzZR8gTmiJjOnrSew49tT8Qxl7-wFEJAk8_IAKmS1KidtNrNxt5GgBsy7Uksk0EXwYmbxLY7ke_yvGNtDTAaR71VWJyTDYJjiu-D-cMrRWGxLUtf0SDQtuf5_7rVNikmuUgxtaNZowstBZog-W8QIpGv7nvfOKchFK-Cf92ApWWU6DH3vN60TQtk9f8e_XLM4Yy2iBEghU58VNegb8mS9Bg-WfiG8Bf8opjj2IxlssqK98AlXPIZ-T-Xar6D9SkOVYTuracOoxSQjOEKHVCtluGQRinP3yxAQvF81ZPp2zO7LbSx2NRB4h2DzcUXSnMbY2PXgw4Sqs7QlJ7miKgrFyseRgikzZNDLv-8jhujkjRfAZ3VZFPy5-LKtG1uLf8erwwLedCqg9ClTLiXMG05uogdXIB8hYjP04ZWPNR_hQwKAEo3yFsS0SSMBOO4ANjc_uzQf7xmnKei0imDfJcufMFCvPuT_F4x6xJzi_DSLOW8s7KDFvFBTBgnTsoVHIAWDXGXM9iebLx26NwgtUcclfm2hidcsuJnS4Qyx9r-AHjxNH7uVNZP3eyjXqH4jrmweLzOGpSuLIGiXfAi7aVFISH5dD4eaq-zkxZgV-Vs8iRD8TlhYb7ETYxM71fw3Ga-rp9hAHY2_pHz3iCs3yIL08u6CGqe6udB10WmTdjk", "dp": "VYi8AKFAbw0yu5xZcf8MKwQwVSCIqZyw7gZDaz5Exz00XKHVWKlUdvqQH52e9GYW84rqdhCINcXctEnT9kfrUJRp6sg40aFWSfZNGvN0ZlwgHsuk8BKXdD0k8evgEH4iomHk5V6b8Au8ilJN3JlI3mW7ZM4aHqODfPXoNAAwHXNX24hnX3on3Y9xZvEoGZKn4WnU7rGZjcsIYphy3IGfIe0BlZYGTHnteAFjsK0ODXoGXSh2ZvhiDKO6fl57lS_h43i5gLsIOtM-T9uGFFe681h4OcM3HQNcYnwvl0RpdKXIKhVn54w7yKc1e3x6bEO5nj0ZPFwAbLWDZ0ljv_SpOw", "dq": "cqloF7Ips92f75WR2xHAuM7GmpywEWZjdiwbHqDQ79cLFbfQxO99J9kpC9kjTRE4T21OdpHOBtEIQYF8mroEHNtI9guBR1sQwMxx_DHyyJ0M1HHrzBawQr9DqqmqfHNkPCLetwv2E0sOd90CvUU6zL9p0f-Npn4-l1r7KsSAn2w5oDy4fb0ZAn4Lc4GtISYNV9SX9rpZN83WlF1oOzOWenTwiWrQneicRdM5L7HxWBs-FQQX5oi32xSf3chwy9o2po2DUD3Ess5BH-Y0lmDH6hEufwHbKRpKzWLxhZwa0BkbFL68ypbeWK-dUNdh5HCCNup0IpCgP1-_6PnQU-vw9Q", "e": "AQAB", "kty": "RSA", "n": "psPFRnGgt4wJK--20KG0M_AgL2B-J0Q4Nrd3duq0lt2kXwtD5MdAmpWpPncQgMzqVT3IyuEjFjHZRw-tv025DbK6PO4k3sZhQwWJjZGte7nKuHzJkQ7tR0ub2DOq4Sg6iBDmBFQ00wotCIfcAbgBT4WLWFu8ne9K4GUjz3vtUCALLryWJeIriJnNl7kKxo8BhbEp567PmECfill9RpPkgm3bp6s2GqAtIwWss6hYY02GPm_cssFwLl_fRBzQcFxg30i3oMgg-Xj5flewEC8sdPXdzXg9PJTLmppfKdnYtgPCTR8a2mTgy_B8vXXrkX636qk_FaT9C0QWxMg6fII_5vqRdx65uAVWqc69bm0ikSz_PgnK5flkwLRQr4D5CvZNCw7xngrEBTP42O0mjtbQJZPYzF3__pdpwqli1Ja1WNEC0EZtzi_2xs7rn07qVv2ZeQ0mObp4gs2uyflQZ-6Mv7S2MnJ00Bn7M_kl6S9a1jRHQDnCe61yfgQr8oGvfI7jaiN-8IMphzdkpK4nO4euWk8M5XQFpIorVyLT2RtIUQlA4L6GQBBuixZxI7nt2AA9ZA4J5cTukYGqT908NJ3g8HEpbWvuZ8kFOXAVi8EJqN9OFDXB5qPDfXFZ6lH7-UmYPKLOjrscX9LUSz_Onu65SVJlylHqorkK0mVOQgo7oaM", "p": "00FDBBfSFIbQYJ8yOCJ7c6ZPLmJxQ7_Fch01KdHJvKjKinb5dDtJMxgZzKwPudBajJWE4ucVMuRYRv4QMJWXov6CaLKN-SHkMFIwWMN-UJAVGT7e_iIq1_BrvFvTeFY9zshpuyFiP4lDNzPH1xX2aD0lCt42l-1rfScm1LIO0LYy1Qqma6m-aaKLAcBpr-6SM3A7-YqNVP3enZevPTz6rgZ_boKICVdR-a3vLNb5w1sP_18I3Fcb0vGCsoxuNh46DaDdSs2jkwPmIrra040vstoXHjOLzlubrrH69WqkbNtHf1DRcKgh7fzgHwuzovC6Bn142cdCmr9aLyVgExFUNw", "q": "yhYlTst5WmxYynEtYU9GBqysQnjJSh1gDKocbJv_7AHdfIMnK8tHdqEByj9DPgao76yZt1fGSN9v1B3PhVYYrhdLvtksdYjUgnu0vjtg7kHsDxwY6H4nZykxWr1tjcWHHmcUnlWU_vtkg1pES8_WJ-dtH0IYe0luPRqVqs8YYKL6He-pRbPj4YJJ6KtYgYFpSKbS3hGHDeEo_Bwz9-cP6Q6NxJwgeOZz8BtryHo4gh77RapZcpxH320Fw993xYewpAt_Bi7OqasH8-DwxMSxK-VuAjgfokxZMX2rQXLGO8xVRTVmXGbAK7deWuvlO1qgCHVxZswzI1aNyMjQ4ze_9Q", "qi": "nh4sH934RRsFA_T68m0sas6i9NaRYLOYHiK-Z4QUHxpG4lXVM1Q80srDWTYX_bGCa6R2xLTnYkICN4Y3vnUFxbfD4iBRKGdmepegF7jajbBAqCpCHDRTJUisd6MF--VOy-HPB2uIpDRw2X-g01k-AEqy7sXu1YEfh9_jEBf2JXV86mylJEqWJJT4zEtu18pq1ZV157-dLezHt1IZ9VJJldXgj1ZQza8T-15vQFfiwx1vLKZI3YiRlYVPEhCSfSqFh1C6Im9vQ8R_4kymnzDXJirzZZPJKr0FoFlJEUX8mFMCHrhqi0-OSMrCRxci_40Gtd08qo40iWjid0szYeAjfA" }`,
				Scopes:       []string{"profile", "signicat.national_id"},
			}

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}

				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					return newMockResponse(http.StatusOK, headers, remoteJwks), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})
		})

		It("initializes client successfully", func() {
			ctx := context.Background()
			client, err := NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)

			Expect(err).To(BeNil())
			Expect(client.provider.Endpoint().AuthURL).To(Equal("https://example.com/oidc/authorize"))
			Expect(client.provider.Endpoint().TokenURL).To(Equal("https://example.com/oidc/token"))
			Expect(client.decryptionKey).NotTo(BeNil())
		})

		It("fails to initialize client if discovery fails", func() {
			body := `{"error":"Internal Server Error"}`
			mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				return newMockResponse(http.StatusInternalServerError, headers, body), nil
			})

			ctx := context.Background()
			client, err := NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)

			Expect(err).NotTo(BeNil())
			Expect(client).To(BeNil())
			Expect(err.Error()).To(Equal(fmt.Sprintf("unable to initialize client: %s: %s", http.StatusText(http.StatusInternalServerError), body)))
		})

		It("fails to initialize client if local key is of invalid format", func() {
			config = Config{
				ClientId:     "exampleClientId",
				ClientSecret: "exampleClientSecret",
				Endpoint:     "https://example.com/oidc",
				RedirectUri:  "https://example.com/redirect",
				LocalJWK:     `{ "d": "Na7lzZR8gTmiJjOnrSew49tT8Qxl7-wFEJAk8_IAKmS1KidtNrNxt5GgBsy7Uksk0EXwYmbxLY7ke_yvGNtDTAaR71VWJyTDYJjiu-D-cMrRWGxLUtf0SDQtuf5_7rVNikmuUgxtaNZowstBZog-W8QIpGv7nvfOKchFK-Cf92ApWWU6DH3vN60TQtk9f8e_XLM4Yy2iBEghU58VNegb8mS9Bg-WfiG8Bf8opjj2IxlssqK98AlXPIZ-T-Xar6D9SkOVYTuracOoxSQjOEKHVCtluGQRinP3yxAQvF81ZPp2zO7LbSx2NRB4h2DzcUXSnMbY2PXgw4Sqs7QlJ7miKgrFyseRgikzZNDLv-8jhujkjRfAZ3VZFPy5-LKtG1uLf8erwwLedCqg9ClTLiXMG05uogdXIB8hYjP04ZWPNR_hQwKAEo3yFsS0SSMBOO4ANjc_uzQf7xmnKei0imDfJcufMFCvPuT_F4x6xJzi_DSLOW8s7KDFvFBTBgnTsoVHIAWDXGXM9iebLx26NwgtUcclfm2hidcsuJnS4Qyx9r-AHjxNH7uVNZP3eyjXqH4jrmweLzOGpSuLIGiXfAi7aVFISH5dD4eaq-zkxZgV-Vs8iRD8TlhYb7ETYxM71fw3Ga-rp9hAHY2_pHz3iCs3yIL08u6CGqe6udB10WmTdjk", "dp": "VYi8AKFAbw0yu5xZcf8MKwQwVSCIqZyw7gZDaz5Exz00XKHVWKlUdvqQH52e9GYW84rqdhCINcXctEnT9kfrUJRp6sg40aFWSfZNGvN0ZlwgHsuk8BKXdD0k8evgEH4iomHk5V6b8Au8ilJN3JlI3mW7ZM4aHqODfPXoNAAwHXNX24hnX3on3Y9xZvEoGZKn4WnU7rGZjcsIYphy3IGfIe0BlZYGTHnteAFjsK0ODXoGXSh2ZvhiDKO6fl57lS_h43i5gLsIOtM-T9uGFFe681h4OcM3HQNcYnwvl0RpdKXIKhVn54w7yKc1e3x6bEO5nj0ZPFwAbLWDZ0ljv_SpOw", "dq": "cqloF7Ips92f75WR2xHAuM7GmpywEWZjdiwbHqDQ79cLFbfQxO99J9kpC9kjTRE4T21OdpHOBtEIQYF8mroEHNtI9guBR1sQwMxx_DHyyJ0M1HHrzBawQr9DqqmqfHNkPCLetwv2E0sOd90CvUU6zL9p0f-Npn4-l1r7KsSAn2w5oDy4fb0ZAn4Lc4GtISYNV9SX9rpZN83WlF1oOzOWenTwiWrQneicRdM5L7HxWBs-FQQX5oi32xSf3chwy9o2po2DUD3Ess5BH-Y0lmDH6hEufwHbKRpKzWLxhZwa0BkbFL68ypbeWK-dUNdh5HCCNup0IpCgP1-_6PnQU-vw9Q", "e": "AQAB", "kty": "INVALID_TYPE", "n": "psPFRnGgt4wJK--20KG0M_AgL2B-J0Q4Nrd3duq0lt2kXwtD5MdAmpWpPncQgMzqVT3IyuEjFjHZRw-tv025DbK6PO4k3sZhQwWJjZGte7nKuHzJkQ7tR0ub2DOq4Sg6iBDmBFQ00wotCIfcAbgBT4WLWFu8ne9K4GUjz3vtUCALLryWJeIriJnNl7kKxo8BhbEp567PmECfill9RpPkgm3bp6s2GqAtIwWss6hYY02GPm_cssFwLl_fRBzQcFxg30i3oMgg-Xj5flewEC8sdPXdzXg9PJTLmppfKdnYtgPCTR8a2mTgy_B8vXXrkX636qk_FaT9C0QWxMg6fII_5vqRdx65uAVWqc69bm0ikSz_PgnK5flkwLRQr4D5CvZNCw7xngrEBTP42O0mjtbQJZPYzF3__pdpwqli1Ja1WNEC0EZtzi_2xs7rn07qVv2ZeQ0mObp4gs2uyflQZ-6Mv7S2MnJ00Bn7M_kl6S9a1jRHQDnCe61yfgQr8oGvfI7jaiN-8IMphzdkpK4nO4euWk8M5XQFpIorVyLT2RtIUQlA4L6GQBBuixZxI7nt2AA9ZA4J5cTukYGqT908NJ3g8HEpbWvuZ8kFOXAVi8EJqN9OFDXB5qPDfXFZ6lH7-UmYPKLOjrscX9LUSz_Onu65SVJlylHqorkK0mVOQgo7oaM", "p": "00FDBBfSFIbQYJ8yOCJ7c6ZPLmJxQ7_Fch01KdHJvKjKinb5dDtJMxgZzKwPudBajJWE4ucVMuRYRv4QMJWXov6CaLKN-SHkMFIwWMN-UJAVGT7e_iIq1_BrvFvTeFY9zshpuyFiP4lDNzPH1xX2aD0lCt42l-1rfScm1LIO0LYy1Qqma6m-aaKLAcBpr-6SM3A7-YqNVP3enZevPTz6rgZ_boKICVdR-a3vLNb5w1sP_18I3Fcb0vGCsoxuNh46DaDdSs2jkwPmIrra040vstoXHjOLzlubrrH69WqkbNtHf1DRcKgh7fzgHwuzovC6Bn142cdCmr9aLyVgExFUNw", "q": "yhYlTst5WmxYynEtYU9GBqysQnjJSh1gDKocbJv_7AHdfIMnK8tHdqEByj9DPgao76yZt1fGSN9v1B3PhVYYrhdLvtksdYjUgnu0vjtg7kHsDxwY6H4nZykxWr1tjcWHHmcUnlWU_vtkg1pES8_WJ-dtH0IYe0luPRqVqs8YYKL6He-pRbPj4YJJ6KtYgYFpSKbS3hGHDeEo_Bwz9-cP6Q6NxJwgeOZz8BtryHo4gh77RapZcpxH320Fw993xYewpAt_Bi7OqasH8-DwxMSxK-VuAjgfokxZMX2rQXLGO8xVRTVmXGbAK7deWuvlO1qgCHVxZswzI1aNyMjQ4ze_9Q", "qi": "nh4sH934RRsFA_T68m0sas6i9NaRYLOYHiK-Z4QUHxpG4lXVM1Q80srDWTYX_bGCa6R2xLTnYkICN4Y3vnUFxbfD4iBRKGdmepegF7jajbBAqCpCHDRTJUisd6MF--VOy-HPB2uIpDRw2X-g01k-AEqy7sXu1YEfh9_jEBf2JXV86mylJEqWJJT4zEtu18pq1ZV157-dLezHt1IZ9VJJldXgj1ZQza8T-15vQFfiwx1vLKZI3YiRlYVPEhCSfSqFh1C6Im9vQ8R_4kymnzDXJirzZZPJKr0FoFlJEUX8mFMCHrhqi0-OSMrCRxci_40Gtd08qo40iWjid0szYeAjfA" }`,
				Scopes:       []string{"profile", "signicat.national_id"},
			}
			ctx := context.Background()
			client, err := NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)

			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("square/go-jose: unknown json web key type 'INVALID_TYPE'"))
			Expect(client).To(BeNil())
		})

		It("fails to initialize client if providers public key fails to marshal", func() {
			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}

				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					remoteJwks := `{
						"keys":[
							{
								"kty":"RSA",
								"e":"AQAB",
								"use":"sig",
								"kid":"any.oidc-signature-preprod.test.jwk.v.1",
								"alg":"RS256",
								"n":"px6mGAGqVTcf8SNBzGF5ZzMQem8QH2wXO1xXEgwQAsBCcVvlpliIj1gkPDux36DYAgdUYy1wM7VhW6FHNhT1yCA7aYteUKB9hKAai3wzQNoUXPHQlKQsWRgTboFRQrkKzPgHHIp8IwZxBFzjCp9W9gdQ_LIQyCyjxoRTR0yg21HB1SC2bh91L2K689IpS9qcb7KBjizVmGqwRCgWtA1lBOKEpgrhPeHnSLcvRWG97ePR5MfmzftWxRftWIlDaIWV_3cnn8WsXH2Qtg4cq5FGBdS30SWHTpYNRuLYfvttivR1uZmx8fnnYEfy3L7lxHbWuVbdkySofQ7yvJWX56GGJw"
							}
							,{
								"kty":"RSA1",
								"e":"AQAB",
								"use":"enc",
								"kid":"any.oidc-encryption-preprod.test.jwk.v.1",
								"alg":"RSA-OAEP",
								"n":"ou9ZQ_e0JSMhOA3fSwzH4h9OHgS8xLbtScHUlQEq9XWRw0i5ZefGWEUCeWJgehxuRMumPdm5_csfSnJLJom3c5cEnloXB53ZFEa6qJ7AEHnSjdMxnIkzcq_4ICQg69fwTac1ZCjxhCraUs6G9LE8b9gN-EHmd8MXuLRxZUkjlgiQKb-XhfDaDA7rd7KMczyxrieZT3q5lk1fjw2V_o_jasowLo8i7s8Wa4S7BAg1ZFv2-oc8PcobbJLsAAIxg3PEn0nDIvNcs6cjjYje2_TrrXMmis2TJquQhLOHjx_yQdzQNfzxC5_GwOZPBKZR1gH1-QxlW7q8jevC2-f_-7FlHw"
							}
						]
					}`
					return newMockResponse(http.StatusOK, headers, remoteJwks), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			ctx := context.Background()
			client, err := NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)

			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("unable to unmarshal keys: square/go-jose: unknown json web key type 'RSA1'"))
			Expect(client).To(BeNil())
		})
	})

	Describe("AuthRequestURL", func() {
		var (
			remoteSignKeyId        string
			remoteSignKey          *rsa.PrivateKey
			remoteSignKeyJwk       *jose.JSONWebKey
			remoteSignKeyMarshaled []byte
			remoteEncKeyId         string
			remoteEncKey           *rsa.PrivateKey
			remoteEncKeyJwk        *jose.JSONWebKey
			remoteEncKeyMarshaled  []byte
			localEncKeyId          string
			localEncKey            *rsa.PrivateKey
			localEncKeyJwk         *jose.JSONWebKey
			localEncKeyMarshaled   []byte
			err                    error
		)

		BeforeEach(func() {
			// Generate signing key for the provider
			remoteSignKeyId = generateId()
			remoteSignKey, err = rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			remoteSignKeyJwk = &jose.JSONWebKey{
				Key:          remoteSignKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        remoteSignKeyId,
				Algorithm:    "RS256",
				Use:          "sig",
			}
			remoteSignKeyJwk.Certificates = nil
			remoteSignKeyMarshaled, err = remoteSignKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			// Generate encryption key for the provider
			remoteEncKeyId = generateId()
			remoteEncKey, err = rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			remoteEncKeyJwk = &jose.JSONWebKey{
				Key:          remoteEncKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        remoteEncKeyId,
				Algorithm:    "RSA-OAEP",
				Use:          "enc",
			}
			remoteEncKeyMarshaled, err = remoteEncKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			// Generate encryption key for the client
			localEncKeyId = generateId()
			localEncKey, err = rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			localEncKeyJwk = &jose.JSONWebKey{
				Key:          localEncKey,
				Certificates: []*x509.Certificate{},
				KeyID:        localEncKeyId,
				Algorithm:    "RSA-OAEP",
				Use:          "enc",
			}
			localEncKeyMarshaled, err = localEncKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			config = Config{
				ClientId:     "exampleClientId",
				ClientSecret: "exampleClientSecret",
				Endpoint:     "https://example.com/oidc",
				RedirectUri:  "https://example.com/redirect",
				LocalJWK:     fmt.Sprintf(`%s`, string(localEncKeyMarshaled)),
				Scopes:       []string{"profile", "signicat.national_id"},
			}

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}

				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{"keys":[%s,%s]}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})
		})

		It("successfully generated authorization request url", func() {
			ctx := context.Background()
			client, err := NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)
			Expect(err).To(BeNil())

			acrValues := "urn:signicat:oidc:method:ftn-op-auth"
			state := generateId()
			opts := map[string]interface{}{
				"acr_values": fmt.Sprintf(acrValues),
				"ui_locales": "en",
			}
			url, err := client.AuthRequestURL(state, opts)
			Expect(err).To(BeNil())
			Expect(strings.Contains(url, "https://example.com/oidc/authorize?request=")).To(BeTrue())

			// TODO: For now we just decrypt the payload and check that the content is correct as mocking the
			//      jose.JSONWebEncryption is not straightforward due to random iv etc. being private fields.
			parts := strings.Split(url, "=")
			parsedJWE, err := jose.ParseEncrypted(parts[1])
			Expect(err).To(BeNil())

			decryptedPayload, err := parsedJWE.Decrypt(remoteEncKey)
			Expect(err).To(BeNil())

			expectedScope := strings.Join(config.Scopes, " ")
			expectedRequestObject := fmt.Sprintf(`{"acr_values":"%s","client_id":"%s","redirect_uri":"%s","response_type":"code","scope":"%s","state":"%s","ui_locales":"en"}`, acrValues, config.ClientId, config.RedirectUri, expectedScope, state)
			Expect(decryptedPayload).To(Equal([]byte(expectedRequestObject)))
		})

		It("fails when provider encryption key is not available", func() {
			mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}

				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{"keys":[%s]}`, remoteSignKeyMarshaled)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			ctx := context.Background()
			client, err := NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)
			Expect(err).To(BeNil())

			acrValues := "urn:signicat:oidc:method:ftn-op-auth"
			state := generateId()
			opts := map[string]interface{}{
				"acr_values": fmt.Sprintf(acrValues),
				"ui_locales": "en",
			}
			url, err := client.AuthRequestURL(state, opts)
			Expect(url).To(BeEmpty())
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("key not found"))
		})

		It("fails when provider encryption key is not valid", func() {
			mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}

				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					remoteEncKeyJwk.Algorithm = "INVALID"
					remoteEncKeyMarshaled, err = remoteEncKeyJwk.MarshalJSON()
					body := fmt.Sprintf(`{"keys":[%s, %s]}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			ctx := context.Background()
			client, err := NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)
			Expect(err).To(BeNil())

			acrValues := "urn:signicat:oidc:method:ftn-op-auth"
			state := generateId()
			opts := map[string]interface{}{
				"acr_values": fmt.Sprintf(acrValues),
				"ui_locales": "en",
			}
			url, err := client.AuthRequestURL(state, opts)
			Expect(url).To(BeEmpty())
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("square/go-jose: unknown/unsupported algorithm"))
		})

		It("fails when encrypter.Encrypter fails", func() {
			mockError := errors.New("encrypter.Encrypt() failed")
			encrypter := mockEncrypter{
				encryption: jose.JSONWebEncryption{},
				opts:       jose.EncrypterOptions{},
				error:      mockError,
			}
			ctx := context.Background()
			contextWithClient := context.WithValue(ctx, oauth2.HTTPClient, mockClient)
			client, err := NewClientMLE(context.WithValue(contextWithClient, EncrypterContextKey, encrypter), &config)
			Expect(err).To(BeNil())

			acrValues := "urn:signicat:oidc:method:ftn-op-auth"
			state := generateId()
			opts := map[string]interface{}{
				"acr_values": fmt.Sprintf(acrValues),
				"ui_locales": "en",
			}
			url, err := client.AuthRequestURL(state, opts)
			Expect(url).To(BeEmpty())
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("encrypter.Encrypt() failed"))
		})
	})

	Describe("Exchange", func() {
		var (
			remoteSignKeyId        string
			remoteSignKey          *rsa.PrivateKey
			remoteSignKeyJwk       *jose.JSONWebKey
			remoteSignKeyMarshaled []byte
			remoteEncKeyId         string
			remoteEncKey           *rsa.PrivateKey
			remoteEncKeyJwk        *jose.JSONWebKey
			remoteEncKeyMarshaled  []byte
			localEncKeyId          string
			localEncKey            *rsa.PrivateKey
			localEncKeyJwk         *jose.JSONWebKey
			localEncKeyPubJwk      *jose.JSONWebKey
			localEncKeyMarshaled   []byte
			err                    error
		)

		BeforeEach(func() {
			// Generate signing key for the provider
			remoteSignKeyId = generateId()
			remoteSignKey, err = rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			remoteSignKeyJwk = &jose.JSONWebKey{
				Key:          remoteSignKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        remoteSignKeyId,
				Algorithm:    "RS256",
				Use:          "sig",
			}
			remoteSignKeyJwk.Certificates = nil
			remoteSignKeyMarshaled, err = remoteSignKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			// Generate encryption key for the provider
			remoteEncKeyId = generateId()
			remoteEncKey, err = rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			remoteEncKeyJwk = &jose.JSONWebKey{
				Key:          remoteEncKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        remoteEncKeyId,
				Algorithm:    "RSA-OAEP",
				Use:          "enc",
			}
			remoteEncKeyMarshaled, err = remoteEncKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			// Generate encryption key for the client
			localEncKeyId = generateId()
			localEncKey, err = rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			localEncKeyJwk = &jose.JSONWebKey{
				Key:          localEncKey,
				Certificates: []*x509.Certificate{},
				KeyID:        localEncKeyId,
				Algorithm:    "RSA-OAEP",
				Use:          "enc",
			}
			localEncKeyPubJwk = &jose.JSONWebKey{
				Key:          localEncKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        localEncKeyId,
				Algorithm:    "RSA-OAEP",
				Use:          "enc",
			}
			localEncKeyMarshaled, err = localEncKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			config = Config{
				ClientId:     "exampleClientId",
				ClientSecret: "exampleClientSecret",
				Endpoint:     "https://example.com/oidc",
				RedirectUri:  "https://example.com/redirect",
				LocalJWK:     fmt.Sprintf(`%s`, string(localEncKeyMarshaled)),
				Scopes:       []string{"profile", "signicat.national_id"},
			}

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}

				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{"keys":[%s,%s]}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})
		})

		It("successfully exchanges authorization code for token", func() {
			ctx := context.Background()
			now := time.Now().UTC()
			in10mins := time.Now().UTC().Add(10 * time.Minute)
			audience := []string{"exampleClientId"}
			idTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  audience,
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
			}

			accessTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  audience,
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
			}

			idToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, idTokenClaims)
			Expect(err).To(BeNil())
			accessToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, accessTokenClaims)
			Expect(err).To(BeNil())

			// encrypt the mocked response with client's public key
			enc := jose.ContentEncryption("A256CBC-HS512")
			alg := jose.KeyAlgorithm(localEncKeyPubJwk.Algorithm)
			encrypterOptions := jose.EncrypterOptions{
				Compression:  "",
				ExtraHeaders: nil,
			}
			encrypterOptions.WithType("JWE")
			encrypter, err := newEncrypter(ctx, localEncKeyPubJwk, enc, alg, encrypterOptions)
			Expect(err).To(BeNil())

			encryptedIdToken, err := encrypter.Encrypt([]byte(idToken))
			Expect(err).To(BeNil())

			serializedIdToken, err := encryptedIdToken.CompactSerialize()
			Expect(err).To(BeNil())

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, serializedIdToken)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
			options := map[string]string{
				"client_id": "exampleClientId",
			}

			code := generateId()
			tokens, err := client.Exchange(code, options)
			Expect(err).To(BeNil())
			Expect(tokens.Oauth2Token.Expiry.UTC().Round(time.Second)).Should(
				BeTemporally("~", accessTokenClaims.Expiry.Time().UTC().Round(time.Second), time.Second))
			Expect(tokens.Oauth2Token.TokenType).To(Equal("Bearer"))
			Expect(tokens.Oauth2Token.RefreshToken).To(Equal("4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4"))
			Expect(tokens.Oauth2Token.AccessToken).To(Equal(accessToken))

			Expect(tokens.IdToken.Expiry.Unix()).To(Equal(in10mins.Unix()))
			Expect(tokens.IdToken.Nonce).To(Equal(idTokenClaims.Nonce))
			Expect(tokens.IdToken.Subject).To(Equal(idTokenClaims.Subject))
			Expect(tokens.IdToken.Audience).To(Equal(audience))
			Expect(tokens.IdToken.IssuedAt).To(Equal(idTokenClaims.IssuedAt.Time()))
			Expect(tokens.IdToken.Issuer).To(Equal(idTokenClaims.Issuer))
		})

		It("fails when provider's token endpoint returns an error", func() {
			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := `{"error": "internal server error"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			ctx := context.Background()
			client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
			options := map[string]string{
				"client_id": "exampleClientId",
			}

			code := generateId()
			tokens, err := client.Exchange(code, options)
			Expect(tokens).To(BeNil())
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("unable to exchange authorization code to token"))
		})

		It("fails when oauth2 token does not contain id_token", func() {
			ctx := context.Background()
			now := time.Now().UTC()
			in10mins := time.Now().UTC().Add(10 * time.Minute)
			audience := []string{"exampleClientId"}

			accessTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  audience,
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
			}

			accessToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, accessTokenClaims)
			Expect(err).To(BeNil())

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600
					}`, accessToken)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
			options := map[string]string{
				"client_id": "exampleClientId",
			}

			code := generateId()
			tokens, err := client.Exchange(code, options)
			Expect(tokens).To(BeNil())
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("no id_token field in oauth2 token"))
		})

		It("fails when id_token cannot be parsed", func() {
			ctx := context.Background()
			now := time.Now().UTC()
			in10mins := time.Now().UTC().Add(10 * time.Minute)
			audience := []string{"exampleClientId"}
			idTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  audience,
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
			}

			accessTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  audience,
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
			}

			idToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, idTokenClaims)
			Expect(err).To(BeNil())
			accessToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, accessTokenClaims)
			Expect(err).To(BeNil())

			// encrypt the mocked response with client's public key
			enc := jose.ContentEncryption("A256CBC-HS512")
			alg := jose.KeyAlgorithm(localEncKeyPubJwk.Algorithm)
			encrypterOptions := jose.EncrypterOptions{
				Compression:  "",
				ExtraHeaders: nil,
			}
			encrypterOptions.WithType("JWE")
			encrypter, err := newEncrypter(ctx, localEncKeyPubJwk, enc, alg, encrypterOptions)
			Expect(err).To(BeNil())

			encryptedIdToken, err := encrypter.Encrypt([]byte(idToken))
			Expect(err).To(BeNil())

			serializedIdToken, err := encryptedIdToken.CompactSerialize()
			Expect(err).To(BeNil())

			// Let's leave the signature part away
			idTokenParts := strings.Split(serializedIdToken, ".")
			idTokenWithoutSignature := strings.Join(idTokenParts[0:4], ".")

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, idTokenWithoutSignature)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
			options := map[string]string{
				"client_id": "exampleClientId",
			}

			code := generateId()
			tokens, err := client.Exchange(code, options)
			Expect(tokens).To(BeNil())
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("unable to parse encrypted id_token"))
		})

		It("fails when id_token cannot be decrypted", func() {
			ctx := context.Background()
			now := time.Now().UTC()
			in10mins := time.Now().UTC().Add(10 * time.Minute)
			audience := []string{"exampleClientId"}
			idTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  audience,
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
			}

			accessTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  audience,
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
			}

			idToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, idTokenClaims)
			Expect(err).To(BeNil())
			accessToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, accessTokenClaims)
			Expect(err).To(BeNil())

			// use wrong key to encrypt the response
			enc := jose.ContentEncryption("A256CBC-HS512")
			alg := jose.KeyAlgorithm(remoteEncKeyJwk.Algorithm)
			encrypterOptions := jose.EncrypterOptions{
				Compression:  "",
				ExtraHeaders: nil,
			}
			encrypterOptions.WithType("JWE")
			encrypter, err := newEncrypter(ctx, remoteEncKeyJwk, enc, alg, encrypterOptions)
			Expect(err).To(BeNil())

			encryptedIdToken, err := encrypter.Encrypt([]byte(idToken))
			Expect(err).To(BeNil())

			serializedIdToken, err := encryptedIdToken.CompactSerialize()
			Expect(err).To(BeNil())

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, serializedIdToken)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
			options := map[string]string{
				"client_id": "exampleClientId",
			}

			code := generateId()
			tokens, err := client.Exchange(code, options)
			Expect(tokens).To(BeNil())
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("unable to decrypt id_token"))
		})

		It("fails when id_token signature cannot be verified", func() {
			ctx := context.Background()
			now := time.Now().UTC()
			in10mins := time.Now().UTC().Add(10 * time.Minute)
			audience := []string{"exampleClientId"}
			idTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  audience,
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
			}

			accessTokenClaims := jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  audience,
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
			}

			// create a wrong key for signing the id_token
			wrongSignKey, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())

			idToken, err := buildSignedJWTToken(wrongSignKey, remoteSignKeyId, idTokenClaims)
			Expect(err).To(BeNil())
			accessToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, accessTokenClaims)
			Expect(err).To(BeNil())

			enc := jose.ContentEncryption("A256CBC-HS512")
			alg := jose.KeyAlgorithm(localEncKeyPubJwk.Algorithm)
			encrypterOptions := jose.EncrypterOptions{
				Compression:  "",
				ExtraHeaders: nil,
			}
			encrypterOptions.WithType("JWE")
			encrypter, err := newEncrypter(ctx, localEncKeyPubJwk, enc, alg, encrypterOptions)
			Expect(err).To(BeNil())

			encryptedIdToken, err := encrypter.Encrypt([]byte(idToken))
			Expect(err).To(BeNil())

			serializedIdToken, err := encryptedIdToken.CompactSerialize()
			Expect(err).To(BeNil())

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, serializedIdToken)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
			options := map[string]string{
				"client_id": "exampleClientId",
			}

			code := generateId()
			tokens, err := client.Exchange(code, options)
			Expect(tokens).To(BeNil())
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("unable to verify id_token signature"))
		})

		Describe("ExchangeWithNonce", func() {
			var (
				remoteSignKeyId        string
				remoteSignKey          *rsa.PrivateKey
				remoteSignKeyJwk       *jose.JSONWebKey
				remoteSignKeyMarshaled []byte
				remoteEncKeyId         string
				remoteEncKey           *rsa.PrivateKey
				remoteEncKeyJwk        *jose.JSONWebKey
				remoteEncKeyMarshaled  []byte
				localEncKeyId          string
				localEncKey            *rsa.PrivateKey
				localEncKeyJwk         *jose.JSONWebKey
				localEncKeyPubJwk      *jose.JSONWebKey
				localEncKeyMarshaled   []byte
				err                    error
			)

			BeforeEach(func() {
				// Generate signing key for the provider
				remoteSignKeyId = generateId()
				remoteSignKey, err = rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).To(BeNil())
				remoteSignKeyJwk = &jose.JSONWebKey{
					Key:          remoteSignKey.Public(),
					Certificates: []*x509.Certificate{},
					KeyID:        remoteSignKeyId,
					Algorithm:    "RS256",
					Use:          "sig",
				}
				remoteSignKeyJwk.Certificates = nil
				remoteSignKeyMarshaled, err = remoteSignKeyJwk.MarshalJSON()
				Expect(err).To(BeNil())

				// Generate encryption key for the provider
				remoteEncKeyId = generateId()
				remoteEncKey, err = rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).To(BeNil())
				remoteEncKeyJwk = &jose.JSONWebKey{
					Key:          remoteEncKey.Public(),
					Certificates: []*x509.Certificate{},
					KeyID:        remoteEncKeyId,
					Algorithm:    "RSA-OAEP",
					Use:          "enc",
				}
				remoteEncKeyMarshaled, err = remoteEncKeyJwk.MarshalJSON()
				Expect(err).To(BeNil())

				// Generate encryption key for the client
				localEncKeyId = generateId()
				localEncKey, err = rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).To(BeNil())
				localEncKeyJwk = &jose.JSONWebKey{
					Key:          localEncKey,
					Certificates: []*x509.Certificate{},
					KeyID:        localEncKeyId,
					Algorithm:    "RSA-OAEP",
					Use:          "enc",
				}
				localEncKeyPubJwk = &jose.JSONWebKey{
					Key:          localEncKey.Public(),
					Certificates: []*x509.Certificate{},
					KeyID:        localEncKeyId,
					Algorithm:    "RSA-OAEP",
					Use:          "enc",
				}
				localEncKeyMarshaled, err = localEncKeyJwk.MarshalJSON()
				Expect(err).To(BeNil())

				config = Config{
					ClientId:     "exampleClientId",
					ClientSecret: "exampleClientSecret",
					Endpoint:     "https://example.com/oidc",
					RedirectUri:  "https://example.com/redirect",
					LocalJWK:     fmt.Sprintf(`%s`, string(localEncKeyMarshaled)),
					Scopes:       []string{"profile", "signicat.national_id"},
				}
			})

			It("successfully exchanges authorization code for token and validates the nonce", func() {
				ctx := context.Background()
				now := time.Now().UTC()
				in10mins := time.Now().UTC().Add(10 * time.Minute)
				audience := []string{"exampleClientId"}
				nonce := generateId()
				idTokenClaims := jwtClaims{
					Issuer:    "https://example.com/oidc",
					Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
					Audience:  audience,
					Expiry:    jwt.NewNumericDate(in10mins),
					NotBefore: jwt.NewNumericDate(now),
					IssuedAt:  jwt.NewNumericDate(now),
					Nonce:     nonce,
				}

				accessTokenClaims := jwtClaims{
					Issuer:    "https://example.com/oidc",
					Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
					Audience:  audience,
					Expiry:    jwt.NewNumericDate(in10mins),
					NotBefore: jwt.NewNumericDate(now),
					IssuedAt:  jwt.NewNumericDate(now),
					ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
				}

				idToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, idTokenClaims)
				Expect(err).To(BeNil())
				accessToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, accessTokenClaims)
				Expect(err).To(BeNil())

				// encrypt the mocked response with client's public key
				enc := jose.ContentEncryption("A256CBC-HS512")
				alg := jose.KeyAlgorithm(localEncKeyPubJwk.Algorithm)
				encrypterOptions := jose.EncrypterOptions{
					Compression:  "",
					ExtraHeaders: nil,
				}
				encrypterOptions.WithType("JWE")
				encrypter, err := newEncrypter(ctx, localEncKeyPubJwk, enc, alg, encrypterOptions)
				Expect(err).To(BeNil())

				encryptedIdToken, err := encrypter.Encrypt([]byte(idToken))
				Expect(err).To(BeNil())

				serializedIdToken, err := encryptedIdToken.CompactSerialize()
				Expect(err).To(BeNil())

				mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					if req.URL.Path == "/oidc/.well-known/openid-configuration" {
						return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
					} else if req.URL.Path == "/oidc/token" {
						body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, serializedIdToken)
						return newMockResponse(http.StatusOK, headers, body), nil
					} else if req.URL.Path == "/oidc/jwks.json" {
						body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
						return newMockResponse(http.StatusOK, headers, body), nil
					} else {
						body := `{"error":"invalid path"}`
						return newMockResponse(http.StatusInternalServerError, headers, body), nil
					}
				})

				client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
				options := map[string]string{
					"client_id": "exampleClientId",
				}

				code := generateId()
				tokens, err := client.ExchangeWithNonce(code, nonce, options)
				Expect(err).To(BeNil())
				Expect(tokens.Oauth2Token.Expiry.Unix()).To(Equal(accessTokenClaims.Expiry.Time().Unix()))
				Expect(tokens.Oauth2Token.TokenType).To(Equal("Bearer"))
				Expect(tokens.Oauth2Token.RefreshToken).To(Equal("4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4"))
				Expect(tokens.Oauth2Token.AccessToken).To(Equal(accessToken))

				Expect(tokens.IdToken.Expiry.Unix()).To(Equal(in10mins.Unix()))
				Expect(tokens.IdToken.Nonce).To(Equal(idTokenClaims.Nonce))
				Expect(tokens.IdToken.Subject).To(Equal(idTokenClaims.Subject))
				Expect(tokens.IdToken.Audience).To(Equal(audience))
				Expect(tokens.IdToken.IssuedAt).To(Equal(idTokenClaims.IssuedAt.Time()))
				Expect(tokens.IdToken.Issuer).To(Equal(idTokenClaims.Issuer))
			})

			It("fails to exchange authorization code for token if nonce does not match the specified nonce", func() {
				ctx := context.Background()
				now := time.Now().UTC()
				in10mins := time.Now().UTC().Add(10 * time.Minute)
				audience := []string{"exampleClientId"}
				invalidNonce := generateId()
				idTokenClaims := jwtClaims{
					Issuer:    "https://example.com/oidc",
					Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
					Audience:  audience,
					Expiry:    jwt.NewNumericDate(in10mins),
					NotBefore: jwt.NewNumericDate(now),
					IssuedAt:  jwt.NewNumericDate(now),
					Nonce:     invalidNonce,
				}

				accessTokenClaims := jwtClaims{
					Issuer:    "https://example.com/oidc",
					Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
					Audience:  audience,
					Expiry:    jwt.NewNumericDate(in10mins),
					NotBefore: jwt.NewNumericDate(now),
					IssuedAt:  jwt.NewNumericDate(now),
					ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
				}

				idToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, idTokenClaims)
				Expect(err).To(BeNil())
				accessToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, accessTokenClaims)
				Expect(err).To(BeNil())

				// encrypt the mocked response with client's public key
				enc := jose.ContentEncryption("A256CBC-HS512")
				alg := jose.KeyAlgorithm(localEncKeyPubJwk.Algorithm)
				encrypterOptions := jose.EncrypterOptions{
					Compression:  "",
					ExtraHeaders: nil,
				}
				encrypterOptions.WithType("JWE")
				encrypter, err := newEncrypter(ctx, localEncKeyPubJwk, enc, alg, encrypterOptions)
				Expect(err).To(BeNil())

				encryptedIdToken, err := encrypter.Encrypt([]byte(idToken))
				Expect(err).To(BeNil())

				serializedIdToken, err := encryptedIdToken.CompactSerialize()
				Expect(err).To(BeNil())

				mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					if req.URL.Path == "/oidc/.well-known/openid-configuration" {
						return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
					} else if req.URL.Path == "/oidc/token" {
						body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, serializedIdToken)
						return newMockResponse(http.StatusOK, headers, body), nil
					} else if req.URL.Path == "/oidc/jwks.json" {
						body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
						return newMockResponse(http.StatusOK, headers, body), nil
					} else {
						body := `{"error":"invalid path"}`
						return newMockResponse(http.StatusInternalServerError, headers, body), nil
					}
				})

				client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
				options := map[string]string{
					"client_id": "exampleClientId",
				}

				code := generateId()
				nonce := generateId()
				tokens, err := client.ExchangeWithNonce(code, nonce, options)
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal(fmt.Sprintf("nonce is not the one specified. expected '%s', got '%s'", nonce, idTokenClaims.Nonce)))
				Expect(tokens).To(BeNil())
			})

			It("fails to exchange when provider's token endpoint returns an error", func() {
				mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					if req.URL.Path == "/oidc/.well-known/openid-configuration" {
						return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
					} else if req.URL.Path == "/oidc/token" {
						body := `{"error": "internal server error"}`
						return newMockResponse(http.StatusInternalServerError, headers, body), nil
					} else if req.URL.Path == "/oidc/jwks.json" {
						body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
						return newMockResponse(http.StatusOK, headers, body), nil
					} else {
						body := `{"error":"invalid path"}`
						return newMockResponse(http.StatusInternalServerError, headers, body), nil
					}
				})

				ctx := context.Background()
				nonce := generateId()
				client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))
				options := map[string]string{
					"client_id": "exampleClientId",
				}

				code := generateId()
				tokens, err := client.ExchangeWithNonce(code, nonce, options)
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("unable to exchange authorization code to token"))
				Expect(tokens).To(BeNil())
			})
		})

		Describe("UserInfo", func() {
			var (
				remoteSignKeyId         string
				remoteSignKey           *rsa.PrivateKey
				remoteSignKeyJwk        *jose.JSONWebKey
				remoteSignKeyMarshaled  []byte
				remoteEncKeyId          string
				remoteEncKey            *rsa.PrivateKey
				remoteEncKeyJwk         *jose.JSONWebKey
				remoteEncKeyMarshaled   []byte
				localEncKeyId           string
				localEncKey             *rsa.PrivateKey
				localEncKeyJwk          *jose.JSONWebKey
				localEncKeyPubJwk       *jose.JSONWebKey
				localEncKeyMarshaled    []byte
				err                     error
				nonce                   string
				idTokenClaims           jwtClaims
				accessTokenClaims       jwtClaims
				now                     time.Time
				in10mins                time.Time
				audience                []string
				idToken                 string
				accessToken             string
				ctx                     context.Context
				encrypter               jose.Encrypter
				encryptedIdToken        *jose.JSONWebEncryption
				serializedIdToken       string
				userInfoClaims          user
				encryptedUserinfoToken  *jose.JSONWebEncryption
				serializedUserInfoToken string
			)

			BeforeEach(func() {
				// Generate signing key for the provider
				remoteSignKeyId = generateId()
				remoteSignKey, err = rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).To(BeNil())
				remoteSignKeyJwk = &jose.JSONWebKey{
					Key:          remoteSignKey.Public(),
					Certificates: []*x509.Certificate{},
					KeyID:        remoteSignKeyId,
					Algorithm:    "RS256",
					Use:          "sig",
				}
				remoteSignKeyJwk.Certificates = nil
				remoteSignKeyMarshaled, err = remoteSignKeyJwk.MarshalJSON()
				Expect(err).To(BeNil())

				// Generate encryption key for the provider
				remoteEncKeyId = generateId()
				remoteEncKey, err = rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).To(BeNil())
				remoteEncKeyJwk = &jose.JSONWebKey{
					Key:          remoteEncKey.Public(),
					Certificates: []*x509.Certificate{},
					KeyID:        remoteEncKeyId,
					Algorithm:    "RSA-OAEP",
					Use:          "enc",
				}
				remoteEncKeyMarshaled, err = remoteEncKeyJwk.MarshalJSON()
				Expect(err).To(BeNil())

				// Generate encryption key for the client
				localEncKeyId = generateId()
				localEncKey, err = rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).To(BeNil())
				localEncKeyJwk = &jose.JSONWebKey{
					Key:          localEncKey,
					Certificates: []*x509.Certificate{},
					KeyID:        localEncKeyId,
					Algorithm:    "RSA-OAEP",
					Use:          "enc",
				}
				localEncKeyPubJwk = &jose.JSONWebKey{
					Key:          localEncKey.Public(),
					Certificates: []*x509.Certificate{},
					KeyID:        localEncKeyId,
					Algorithm:    "RSA-OAEP",
					Use:          "enc",
				}
				localEncKeyMarshaled, err = localEncKeyJwk.MarshalJSON()
				Expect(err).To(BeNil())

				now = time.Now().UTC()
				in10mins = time.Now().UTC().Add(10 * time.Minute)
				audience = []string{"exampleClientId"}
				nonce = generateId()
				idTokenClaims = jwtClaims{
					Issuer:    "https://example.com/oidc",
					Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
					Audience:  audience,
					Expiry:    jwt.NewNumericDate(in10mins),
					NotBefore: jwt.NewNumericDate(now),
					IssuedAt:  jwt.NewNumericDate(now),
					Nonce:     nonce,
				}

				accessTokenClaims = jwtClaims{
					Issuer:    "https://example.com/oidc",
					Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
					Audience:  audience,
					Expiry:    jwt.NewNumericDate(in10mins),
					NotBefore: jwt.NewNumericDate(now),
					IssuedAt:  jwt.NewNumericDate(now),
					ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
				}

				// TODO: add "ftn.idpId":"fi-op"
				userInfoClaims = user{
					Subject:    "IY1kAqvxOLMOZBDGuMpG6lcTAi_qJihr",
					Name:       "Väinö Tunnistus",
					GivenName:  "Väinö",
					Locale:     "FI",
					SSN:        "123456-123A",
					FamilyName: "Tunnistus",
				}

				idToken, err = buildSignedJWTToken(remoteSignKey, remoteSignKeyId, idTokenClaims)
				Expect(err).To(BeNil())
				accessToken, err = buildSignedJWTToken(remoteSignKey, remoteSignKeyId, accessTokenClaims)
				Expect(err).To(BeNil())

				ctx = context.Background()
				enc := jose.ContentEncryption("A256CBC-HS512")
				alg := jose.KeyAlgorithm(localEncKeyPubJwk.Algorithm)
				encrypterOptions := jose.EncrypterOptions{
					Compression:  "",
					ExtraHeaders: nil,
				}
				encrypterOptions.WithType("JWE")
				encrypterOptions.WithContentType("JWT")
				encrypter, err = newEncrypter(ctx, localEncKeyPubJwk, enc, alg, encrypterOptions)
				Expect(err).To(BeNil())

				encryptedIdToken, err = encrypter.Encrypt([]byte(idToken))
				Expect(err).To(BeNil())

				serializedIdToken, err = encryptedIdToken.CompactSerialize()
				Expect(err).To(BeNil())

				userInfoToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, userInfoClaims)
				Expect(err).To(BeNil())

				encryptedUserinfoToken, err = encrypter.Encrypt([]byte(userInfoToken))
				Expect(err).To(BeNil())

				serializedUserInfoToken, err = encryptedUserinfoToken.CompactSerialize()
				Expect(err).To(BeNil())

				mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					if req.URL.Path == "/oidc/.well-known/openid-configuration" {
						return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
					} else if req.URL.Path == "/oidc/token" {
						body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, serializedIdToken)
						return newMockResponse(http.StatusOK, headers, body), nil
					} else if req.URL.Path == "/oidc/jwks.json" {
						body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
						return newMockResponse(http.StatusOK, headers, body), nil
					} else if req.URL.Path == "/oidc/userinfo" {
						return newMockResponse(http.StatusOK, headers, serializedUserInfoToken), nil
					} else {
						body := `{"error":"invalid path"}`
						return newMockResponse(http.StatusNotFound, headers, body), nil
					}
				})

				config = Config{
					ClientId:     "exampleClientId",
					ClientSecret: "exampleClientSecret",
					Endpoint:     "https://example.com/oidc",
					RedirectUri:  "https://example.com/redirect",
					LocalJWK:     fmt.Sprintf(`%s`, string(localEncKeyMarshaled)),
					Scopes:       []string{"profile", "signicat.national_id"},
				}
			})

			It("successfully fetches the user info", func() {
				client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

				var userInfo user
				oauth2Token := oauth2.Token{}
				err = client.UserInfo(oauth2.StaticTokenSource(&oauth2Token), &userInfo)
				Expect(err).To(BeNil())
				Expect(userInfo.Name).To(Equal(userInfoClaims.Name))
				Expect(userInfo.Subject).To(Equal(userInfoClaims.Subject))
				Expect(userInfo.GivenName).To(Equal(userInfoClaims.GivenName))
				Expect(userInfo.Locale).To(Equal(userInfoClaims.Locale))
				Expect(userInfo.FamilyName).To(Equal(userInfoClaims.FamilyName))
			})

			It("fails when userinfo endpoint responds with HTTP 500", func() {
				mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					path := req.URL.Path
					if path == "/oidc/.well-known/openid-configuration" {
						return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
					} else if req.URL.Path == "/oidc/token" {
						body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, serializedIdToken)
						return newMockResponse(http.StatusOK, headers, body), nil
					} else if path == "/oidc/jwks.json" {
						return newMockResponse(http.StatusOK, headers, remoteJwks), nil
					} else if path == "/oidc/userinfo" {
						body := `{"error": "internal server error"}`
						return newMockResponse(http.StatusInternalServerError, headers, body), nil
					} else {
						body := `{"error":"invalid path"}`
						return newMockResponse(http.StatusInternalServerError, headers, body), nil
					}
				})

				oauth2Token := oauth2.Token{}
				client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

				var userInfo user
				err = client.UserInfo(oauth2.StaticTokenSource(&oauth2Token), &userInfo)
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("unable to fetch user info, received status: Internal Server Error"))
			})

			It("fails when userinfo response cannot be decrypted", func() {
				remoteWrongEncKeyId := generateId()
				remoteWrongEncKey, err := rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).To(BeNil())
				remoteWrongEncKeyJwk := &jose.JSONWebKey{
					Key:          remoteWrongEncKey.Public(),
					Certificates: []*x509.Certificate{},
					KeyID:        remoteWrongEncKeyId,
					Algorithm:    "RSA-OAEP",
					Use:          "enc",
				}

				userInfoToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, userInfoClaims)
				Expect(err).To(BeNil())

				// encrypt the mocked response with client's public key
				enc := jose.ContentEncryption("A256CBC-HS512")
				alg := jose.KeyAlgorithm(remoteWrongEncKeyJwk.Algorithm)
				encrypterOptions := jose.EncrypterOptions{
					Compression:  "",
					ExtraHeaders: nil,
				}
				encrypterOptions.WithType("JWE")
				encrypterOptions.WithContentType("JWT")
				wrongEncrypter, err := newEncrypter(ctx, remoteWrongEncKeyJwk, enc, alg, encrypterOptions)
				Expect(err).To(BeNil())

				encryptedUserinfoToken, err := wrongEncrypter.Encrypt([]byte(userInfoToken))
				Expect(err).To(BeNil())

				serializedUserInfoToken, err := encryptedUserinfoToken.CompactSerialize()
				Expect(err).To(BeNil())

				mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					path := req.URL.Path
					if path == "/oidc/.well-known/openid-configuration" {
						return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
					} else if req.URL.Path == "/oidc/token" {
						body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, serializedIdToken)
						return newMockResponse(http.StatusOK, headers, body), nil
					} else if path == "/oidc/jwks.json" {
						return newMockResponse(http.StatusOK, headers, remoteJwks), nil
					} else if path == "/oidc/userinfo" {
						return newMockResponse(http.StatusOK, headers, serializedUserInfoToken), nil
					} else {
						body := `{"error":"invalid path"}`
						return newMockResponse(http.StatusInternalServerError, headers, body), nil
					}
				})

				client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

				var userInfo user
				oauth2Token := oauth2.Token{}
				err = client.UserInfo(oauth2.StaticTokenSource(&oauth2Token), &userInfo)
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("unable to decrypt payload: square/go-jose: error in cryptographic primitive"))
			})

			It("fails when request to userinfo endpoint fails", func() {
				mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					path := req.URL.Path
					if path == "/oidc/.well-known/openid-configuration" {
						return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
					} else if path == "/oidc/jwks.json" {
						return newMockResponse(http.StatusOK, headers, remoteJwks), nil
					} else if path == "/oidc/userinfo" {
						body := `{"error": "internal server error"}`
						return newMockResponse(http.StatusInternalServerError, headers, body),
							errors.New("request failed")
					} else {
						body := `{"error":"invalid path"}`
						return newMockResponse(http.StatusInternalServerError, headers, body), nil
					}
				})

				ctx := context.Background()
				client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

				var userInfo user
				oauth2Token := oauth2.Token{}
				err = client.UserInfo(oauth2.StaticTokenSource(&oauth2Token), &userInfo)
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("unable to execute request: Get \"https://example.com/oidc/userinfo\": request failed"))
			})

			It("fails when userinfo response JWT cannot be parsed", func() {
				// create encrypter with missing cty header to invalidate the parsing of the response
				enc := jose.ContentEncryption("A256CBC-HS512")
				alg := jose.KeyAlgorithm(remoteEncKeyJwk.Algorithm)
				options := jose.EncrypterOptions{
					Compression:  "",
					ExtraHeaders: nil,
				}
				options.WithType("JWE")

				encrypter, err := jose.NewEncrypter(enc, jose.Recipient{
					Algorithm: alg,
					Key:       remoteEncKeyJwk,
				}, &options)
				Expect(err).To(BeNil())

				userInfoToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, userInfoClaims)
				Expect(err).To(BeNil())

				encryptedUserinfoToken, err := encrypter.Encrypt([]byte(userInfoToken))
				Expect(err).To(BeNil())

				serializedUserInfoToken, err := encryptedUserinfoToken.CompactSerialize()
				Expect(err).To(BeNil())

				mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					path := req.URL.Path
					if path == "/oidc/.well-known/openid-configuration" {
						return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
					} else if req.URL.Path == "/oidc/token" {
						body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, serializedIdToken)
						return newMockResponse(http.StatusOK, headers, body), nil
					} else if path == "/oidc/jwks.json" {
						return newMockResponse(http.StatusOK, headers, remoteJwks), nil
					} else if path == "/oidc/userinfo" {
						return newMockResponse(http.StatusOK, headers, serializedUserInfoToken), nil
					} else {
						body := `{"error":"invalid path"}`
						return newMockResponse(http.StatusInternalServerError, headers, body), nil
					}
				})

				client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

				var userInfo user
				oauth2Token := oauth2.Token{}
				err = client.UserInfo(oauth2.StaticTokenSource(&oauth2Token), &userInfo)
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("unable to parse encrypted response: square/go-jose/jwt: expected content type to be JWT (cty header)"))
			})

			It("fails when response signature cannot be verified", func() {
				mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					path := req.URL.Path
					if path == "/oidc/.well-known/openid-configuration" {
						return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
					} else if req.URL.Path == "/oidc/token" {
						body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, serializedIdToken)
						return newMockResponse(http.StatusOK, headers, body), nil
					} else if path == "/oidc/jwks.json" {
						body := fmt.Sprintf(`{"keys": [%s]}`, remoteEncKeyMarshaled)
						return newMockResponse(http.StatusOK, headers, body), nil
					} else if path == "/oidc/userinfo" {
						return newMockResponse(http.StatusOK, headers, serializedUserInfoToken), nil
					} else {
						body := `{"error":"invalid path"}`
						return newMockResponse(http.StatusInternalServerError, headers, body), nil
					}
				})

				client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

				var userInfo user
				oauth2Token := oauth2.Token{}
				err = client.UserInfo(oauth2.StaticTokenSource(&oauth2Token), &userInfo)
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal(fmt.Sprintf("unable to find key with keyId '%s'", remoteSignKeyId)))
			})
		})
	})

	Describe("HandleCallback", func() {
		var (
			remoteSignKeyId         string
			remoteSignKey           *rsa.PrivateKey
			remoteSignKeyJwk        *jose.JSONWebKey
			remoteSignKeyMarshaled  []byte
			remoteEncKeyId          string
			remoteEncKey            *rsa.PrivateKey
			remoteEncKeyJwk         *jose.JSONWebKey
			remoteEncKeyMarshaled   []byte
			localEncKeyId           string
			localEncKey             *rsa.PrivateKey
			localEncKeyJwk          *jose.JSONWebKey
			localEncKeyPubJwk       *jose.JSONWebKey
			localEncKeyMarshaled    []byte
			err                     error
			nonce                   string
			idTokenClaims           jwtClaims
			accessTokenClaims       jwtClaims
			now                     time.Time
			in10mins                time.Time
			audience                []string
			idToken                 string
			accessToken             string
			ctx                     context.Context
			encrypter               jose.Encrypter
			encryptedIdToken        *jose.JSONWebEncryption
			serializedIdToken       string
			userInfoClaims          user
			encryptedUserinfoToken  *jose.JSONWebEncryption
			serializedUserInfoToken string
		)

		BeforeEach(func() {
			// Generate signing key for the provider
			remoteSignKeyId = generateId()
			remoteSignKey, err = rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			remoteSignKeyJwk = &jose.JSONWebKey{
				Key:          remoteSignKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        remoteSignKeyId,
				Algorithm:    "RS256",
				Use:          "sig",
			}
			remoteSignKeyJwk.Certificates = nil
			remoteSignKeyMarshaled, err = remoteSignKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			// Generate encryption key for the provider
			remoteEncKeyId = generateId()
			remoteEncKey, err = rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			remoteEncKeyJwk = &jose.JSONWebKey{
				Key:          remoteEncKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        remoteEncKeyId,
				Algorithm:    "RSA-OAEP",
				Use:          "enc",
			}
			remoteEncKeyMarshaled, err = remoteEncKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			// Generate encryption key for the client
			localEncKeyId = generateId()
			localEncKey, err = rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil())
			localEncKeyJwk = &jose.JSONWebKey{
				Key:          localEncKey,
				Certificates: []*x509.Certificate{},
				KeyID:        localEncKeyId,
				Algorithm:    "RSA-OAEP",
				Use:          "enc",
			}
			localEncKeyPubJwk = &jose.JSONWebKey{
				Key:          localEncKey.Public(),
				Certificates: []*x509.Certificate{},
				KeyID:        localEncKeyId,
				Algorithm:    "RSA-OAEP",
				Use:          "enc",
			}
			localEncKeyMarshaled, err = localEncKeyJwk.MarshalJSON()
			Expect(err).To(BeNil())

			now = time.Now().UTC()
			in10mins = time.Now().UTC().Add(10 * time.Minute)
			audience = []string{"exampleClientId"}
			nonce = generateId()
			idTokenClaims = jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  audience,
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				Nonce:     nonce,
			}

			accessTokenClaims = jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  audience,
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
			}

			userInfoClaims = user{
				Subject:    "IY1kAqvxOLMOZBDGuMpG6lcTAi_qJihr",
				Name:       "Väinö Tunnistus",
				GivenName:  "Väinö",
				Locale:     "FI",
				SSN:        "123456-123A",
				FamilyName: "Tunnistus",
			}

			idToken, err = buildSignedJWTToken(remoteSignKey, remoteSignKeyId, idTokenClaims)
			Expect(err).To(BeNil())
			accessToken, err = buildSignedJWTToken(remoteSignKey, remoteSignKeyId, accessTokenClaims)
			Expect(err).To(BeNil())

			ctx = context.Background()
			enc := jose.ContentEncryption("A256CBC-HS512")
			alg := jose.KeyAlgorithm(localEncKeyPubJwk.Algorithm)
			encrypterOptions := jose.EncrypterOptions{
				Compression:  "",
				ExtraHeaders: nil,
			}
			encrypterOptions.WithType("JWE")
			encrypterOptions.WithContentType("JWT")
			encrypter, err = newEncrypter(ctx, localEncKeyPubJwk, enc, alg, encrypterOptions)
			Expect(err).To(BeNil())

			encryptedIdToken, err = encrypter.Encrypt([]byte(idToken))
			Expect(err).To(BeNil())

			serializedIdToken, err = encryptedIdToken.CompactSerialize()
			Expect(err).To(BeNil())

			userInfoToken, err := buildSignedJWTToken(remoteSignKey, remoteSignKeyId, userInfoClaims)
			Expect(err).To(BeNil())

			encryptedUserinfoToken, err = encrypter.Encrypt([]byte(userInfoToken))
			Expect(err).To(BeNil())

			serializedUserInfoToken, err = encryptedUserinfoToken.CompactSerialize()
			Expect(err).To(BeNil())

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, serializedIdToken)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/userinfo" {
					return newMockResponse(http.StatusOK, headers, serializedUserInfoToken), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusNotFound, headers, body), nil
				}
			})

			config = Config{
				ClientId:     "exampleClientId",
				ClientSecret: "exampleClientSecret",
				Endpoint:     "https://example.com/oidc",
				RedirectUri:  "https://example.com/redirect",
				LocalJWK:     fmt.Sprintf(`%s`, string(localEncKeyMarshaled)),
				Scopes:       []string{"profile", "signicat.national_id"},
			}
		})

		It("successfully handles the callback", func() {
			ctx := context.Background()
			client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			var userInfo user
			code := generateId()
			state := generateId()
			queryParams := url.Values{
				"code":  {code},
				"state": {state},
			}
			err = client.HandleCallback(state, nonce, queryParams, &userInfo)
			Expect(err).To(BeNil())
			Expect(userInfo.Name).To(Equal(userInfoClaims.Name))
			Expect(userInfo.Subject).To(Equal(userInfoClaims.Subject))
			Expect(userInfo.GivenName).To(Equal(userInfoClaims.GivenName))
			Expect(userInfo.Locale).To(Equal(userInfoClaims.Locale))
			Expect(userInfo.FamilyName).To(Equal(userInfoClaims.FamilyName))
		})

		It("fails if nonce does not match the one defined in authorization request", func() {
			nonMatchingNonce := generateId()
			idTokenClaims = jwtClaims{
				Issuer:    "https://example.com/oidc",
				Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
				Audience:  []string{"exampleClientId"},
				Expiry:    jwt.NewNumericDate(in10mins),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				Nonce:     nonMatchingNonce,
			}

			idToken, err = buildSignedJWTToken(remoteSignKey, remoteSignKeyId, idTokenClaims)
			Expect(err).To(BeNil())
			encryptedIdToken, err = encrypter.Encrypt([]byte(idToken))
			Expect(err).To(BeNil())
			serializedIdToken, err = encryptedIdToken.CompactSerialize()
			Expect(err).To(BeNil())

			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := fmt.Sprintf(`{
						"access_token":"%s",
						"token_type":"Bearer",
						"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
						"scope":"openid profile",
						"expires_in":600,
						"id_token":"%s"
					}`, accessToken, serializedIdToken)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})

			ctx := context.Background()
			client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			var userInfo user
			code := generateId()
			state := generateId()
			nonce := generateId()
			queryParams := url.Values{
				"code":  {code},
				"state": {state},
			}
			err = client.HandleCallback(state, nonce, queryParams, &userInfo)
			Expect(userInfo).To(Equal(user{}))
			Expect(err).NotTo(BeNil())
			expectedErr := fmt.Sprintf("nonce is not the one specified. expected '%s', got '%s'", nonce, nonMatchingNonce)
			Expect(err.Error()).To(Equal(expectedErr))
		})

		It("fails when userinfo endpoint fails to return user info", func() {
			mockClient = newMockClient(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration), nil
				} else if req.URL.Path == "/oidc/token" {
					body := `{"error": "internal server error"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				} else if req.URL.Path == "/oidc/jwks.json" {
					body := fmt.Sprintf(`{
							"keys":[
								%s,
								%s
						]
					}`, remoteSignKeyMarshaled, remoteEncKeyMarshaled)
					return newMockResponse(http.StatusOK, headers, body), nil
				} else if req.URL.Path == "/oidc/userinfo" {
					body := `{
						"sub":"IY1kAqvxOLMOZBDGuMpG6lcTAi_qJihr",
						"name":"Väinö Tunnistus",
						"given_name":"Väinö",
						"locale":"FI",
						"signicat.national_id": "123456-123A",
						"ftn.idpId":"fi-op",
						"family_name":"Tunnistus"
					}`
					return newMockResponse(http.StatusOK, headers, body), nil
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body), nil
				}
			})
			ctx := context.Background()
			client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			code := generateId()
			var userInfo user
			state := generateId()
			queryParams := url.Values{
				"code":  {code},
				"state": {state},
			}
			err = client.HandleCallback(state, "", queryParams, userInfo)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("unable to exchange authorization code to token"))
		})

		It("fails when query params contain error parameter", func() {
			ctx := context.Background()
			client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			var userInfo user
			state := generateId()
			authErr := "process failed"
			authErrDesc := "user cancelled the authorization process"
			queryParams := url.Values{
				"error":             {authErr},
				"error_description": {authErrDesc},
				"state":             {state},
			}
			expectedError := fmt.Sprintf("authorization failed. error: %s, description: %s", authErr, authErrDesc)
			err = client.HandleCallback(state, "", queryParams, userInfo)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal(expectedError))
		})

		It("fails when the state does not match", func() {
			ctx := context.Background()
			client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			var userInfo user
			state := generateId()
			state2 := generateId()
			code := generateId()
			queryParams := url.Values{
				"code":  {code},
				"state": {state},
			}
			expectedError := "received state does not match the defined state"
			err = client.HandleCallback(state2, "", queryParams, userInfo)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal(expectedError))
		})

		It("fails when authorization code is missing", func() {
			ctx := context.Background()
			client := Must(NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config))

			var userInfo user
			state := generateId()
			queryParams := url.Values{
				"state": {state},
			}
			expectedError := "authorization code missing"
			err = client.HandleCallback(state, "", queryParams, userInfo)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal(expectedError))
		})
	})
})

func buildSignedJWTToken(key *rsa.PrivateKey, keyId string, claims interface{}) (string, error) {
	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", keyId)

	alg := jose.SignatureAlgorithm("RS256")
	signingKey := jose.SigningKey{
		Algorithm: alg,
		Key:       key,
	}
	rsaSigner, err := jose.NewSigner(signingKey, &signerOpts)
	Expect(err).To(BeNil())

	return jwt.Signed(rsaSigner).Claims(claims).CompactSerialize()
}

func generateId() string {
	id := uuid.Must(uuid.NewV4())
	return id.String()
}
