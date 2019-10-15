package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
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

type MockRoundTrip func(request *http.Request) *http.Response

func (m MockRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return m(request), nil
}

func newMockClient(fn MockRoundTrip) *http.Client {
	return &http.Client{
		Transport: fn,
	}
}

func newMockResponse(statusCode int, headers http.Header, body string) *http.Response {
	b := bytes.NewBufferString(body)
	mockBody := ioutil.NopCloser(b)
	return &http.Response{
		Status:        http.StatusText(statusCode),
		StatusCode:    statusCode,
		Header:        headers,
		Body:          mockBody,
		ContentLength: int64(b.Len()),
	}
}

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

var _ = Describe("OIDCClient Tests", func() {
	var (
		mockClient *http.Client
		config     Config
	)

	Describe("OIDCClient tests", func() {
		BeforeEach(func() {
			config = Config{
				ClientId:     "exampleClientId",
				ClientSecret: "exampleClientSecret",
				Endpoint:     "https://example.com/oidc",
				RedirectUri:  "http://localhost:5000/redirect",
				Scopes:       []string{"openid", "profile", "signicat.national_id"},
			}

			mockClient = newMockClient(func(req *http.Request) *http.Response {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration)
				} else if req.URL.Path == "/oidc/jwks.json" {
					return newMockResponse(http.StatusOK, headers, remoteJwks)
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body)
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
			})

			It("fails to initialize client if discovery fails", func() {
				body := `{"error":"Internal Server Error"}`
				mockClient := newMockClient(func(req *http.Request) *http.Response {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					return newMockResponse(http.StatusInternalServerError, headers, body)
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
				options := map[string]string{
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
		})

		Describe("Exchange", func() {
			BeforeEach(func() {
				config = Config{
					ClientId:     "demo-preprod", // Must be demo-preprod or else the token verification will fail as the token audience does not contain the correct client id
					ClientSecret: "exampleClientSecret",
					Endpoint:     "https://example.com/oidc",
					RedirectUri:  "http://localhost:5000/redirect",
					Scopes:       []string{"openid", "profile", "signicat.national_id"},
				}

				mockClient = newMockClient(func(req *http.Request) *http.Response {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					path := req.URL.Path
					if path == "/oidc/.well-known/openid-configuration" {
						return newMockResponse(http.StatusOK, headers, openidConfiguration)
					} else if path == "/oidc/token" {
						body := `{
							"access_token":"eyJraWQiOiJhbnkub2lkYy1zaWduYXR1cmUtcHJlcHJvZC50ZXN0Lmp3ay52LjEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiItWC1RLTFnbUktSWxSLXpoOGdkc0NOZ0FqUlowWmpYOSIsInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIl0sInNubSI6ImRlbW8iLCJpc3MiOiJodHRwczpcL1wvcHJlcHJvZC5zaWduaWNhdC5jb21cL29pZGMiLCJleHAiOjE1NzA3MTc1NTEsImlhdCI6MTU3MDcxNTc1MSwianRpIjoiRnlzVkVPaENURzJUSjg0ZWxIZDVOTDZkNVhtWUp2OC0iLCJjaWQiOiJkZW1vLXByZXByb2QifQ.Lm8pqn0F3euTOttBz3VEryIz-VoeBAABDxjhcCC3hMqa5-nl5SJIg7xIoCQ8hSsqcRmxPRSF6gbyKJU52TwH3miVVYoemBzVL0cqxwDXxBc5oZhUSEr3CkVME34URd-q9ThQugJXWzSrrvxtgdbklb_eEijF1BuZc0zOMtsLXdV88foy-p6PeGQ7EhRpsoa_DEB88zzE5AGpStG4PLotYs0ev3E5sLgViAsqAKrPV26V2gHpdEnYFqAJz6AoSA7LntM_9im1TF3VnLRt467-2a8qYPuDcsnjudjajElmAYEZ9qQ6B0cUtNJV-dU8aDF1vJ7GpgolY05psUJVXcbNAg",
							"token_type":"Bearer",
							"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
							"scope":"openid profile",
							"expires_in":1800,
							"id_token":"eyJraWQiOiJhbnkub2lkYy1zaWduYXR1cmUtcHJlcHJvZC50ZXN0Lmp3ay52LjEiLCJhbGciOiJSUzI1NiJ9.eyJhY3IiOiJ1cm46c2lnbmljYXQ6b2lkYzptZXRob2Q6aWRpbiIsInN1YiI6Ii1YLVEtMWdtSS1JbFItemg4Z2RzQ05nQWpSWjBaalg5IiwiYXVkIjoiZGVtby1wcmVwcm9kIiwibmJmIjoxNTcwNzE1NzUxLCJhdXRoX3RpbWUiOjE1NzA3MTU3NDAsImFtciI6InVybjprc2k6bmFtZXM6U0FNTDoyLjA6YWM6aURJTiIsImlzcyI6Imh0dHBzOlwvXC9wcmVwcm9kLnNpZ25pY2F0LmNvbVwvb2lkYyIsImV4cCI6MTU3MDcxOTM1MSwiaWF0IjoxNTcwNzE1NzUxfQ.T9h62zn_IWGu4s9yyW0sf7HmGW2zLZajTF56l-_xDTG_tyTAryuKW9O6fixLkZoz8Mfh-AKBSqPt5bj8Z642mmVNaFZLhrvjtTyO_xvQc448BBKmVu7doPH4fBAFeA8IX-kUGEPN6djH3gLC75UifxG_URkHTqJSCpZXVNIjAy5g7m2_DISm4n3-uijWMMnwQoGPn1FvM2agwNIuMPLuGmmF5-YLGs8T7_9AasSUlYhMpjiATkolcajrXSMAizCKreRldxXK8dLwlh0UyFcosaHyVr0hiAa3LRV9i4crcfyKsh-NfFw6eSvZfmMA-UWt-jlSpB2g8mQIqPxJbbr8Xg"
						}`
						return newMockResponse(http.StatusOK, headers, body)
					} else if path == "/oidc/jwks.json" {
						return newMockResponse(http.StatusOK, headers, remoteJwks)
					} else {
						body := `{"error":"invalid path"}`
						return newMockResponse(http.StatusInternalServerError, headers, body)
					}
				})
			})

			It("successfully exchanges authorization code for token", func() {
				keyId := generateId()
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: keyId, Algorithm: "RS256", Use: "sig"}
				keyJWKSMarshaled, err := keyJWK.MarshalJSON()

				now := time.Now()
				in10mins := time.Now().Add(10 * time.Minute)
				idTokenClaims := jwt.Claims{
					Issuer:    "https://example.com/oidc",
					Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
					Audience:  []string{"demo-preprod"},
					Expiry:    jwt.NewNumericDate(in10mins),
					NotBefore: jwt.NewNumericDate(now),
					IssuedAt:  jwt.NewNumericDate(now),
				}

				accessTokenClaims := jwt.Claims{
					Issuer:    "https://example.com/oidc",
					Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
					Audience:  []string{"demo-preprod"},
					Expiry:    jwt.NewNumericDate(in10mins),
					NotBefore: jwt.NewNumericDate(now),
					IssuedAt:  jwt.NewNumericDate(now),
					ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
				}

				idToken, err := buildSignedJWTToken(key, keyId, idTokenClaims)
				if err != nil {
					Fail("unable to create idToken")
				}
				accessToken, err := buildSignedJWTToken(key, keyId, accessTokenClaims)
				if err != nil {
					fmt.Println(err)
					Fail("unable to create accessToken")
				}

				mockClient = newMockClient(func(req *http.Request) *http.Response {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					if req.URL.Path == "/oidc/.well-known/openid-configuration" {
						return newMockResponse(http.StatusOK, headers, openidConfiguration)
					} else if req.URL.Path == "/oidc/token" {
						body := fmt.Sprintf(`{
							"access_token":"%s",
							"token_type":"Bearer",
							"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
							"scope":"openid profile",
							"expires_in":600,
							"id_token":"%s"
						}`, accessToken, idToken)
						return newMockResponse(http.StatusOK, headers, body)
					} else if req.URL.Path == "/oidc/jwks.json" {
						body := fmt.Sprintf(`{
								"keys":[
									%s,
									%s
							]
						}`, keyJWKSMarshaled, remoteEncKey)
						return newMockResponse(http.StatusOK, headers, body)
					} else {
						body := `{"error":"invalid path"}`
						return newMockResponse(http.StatusInternalServerError, headers, body)
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
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: keyId, Algorithm: "RS256", Use: "sig"}
				keyJWKSMarshaled, err := keyJWK.MarshalJSON()
				if err != nil {
					Fail("unable to marshal generated public key")
				}

				in10mins := time.Now().Add(10 * time.Minute)
				accessTokenClaims := jwt.Claims{
					Issuer:    "https://example.com/oidc",
					Subject:   "-X-Q-1gmI-IlR-zh8gdsCNgAjRZ0ZjX9",
					Audience:  []string{"demo-preprod"},
					Expiry:    jwt.NewNumericDate(in10mins),
					NotBefore: jwt.NewNumericDate(time.Now()),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					ID:        "FysVEOhCTG2TJ84elHd5NL6d5XmYJv8-",
				}

				accessToken, err := buildSignedJWTToken(key, keyId, accessTokenClaims)
				if err != nil {
					Fail("unable to create accessToken")
				}
				mockClient = newMockClient(func(req *http.Request) *http.Response {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					if req.URL.Path == "/oidc/.well-known/openid-configuration" {
						return newMockResponse(http.StatusOK, headers, openidConfiguration)
					} else if req.URL.Path == "/oidc/token" {
						body := fmt.Sprintf(`{
							"access_token":"%s",
							"token_type":"Bearer",
							"refresh_token":"4DrsxnobxT09oQ4r0JiAhuEXWvnfLdh4",
							"scope":"openid profile",
							"expires_in":600
						}`, accessToken)
						return newMockResponse(http.StatusOK, headers, body)
					} else if req.URL.Path == "/oidc/jwks.json" {
						body := fmt.Sprintf(`{
								"keys":[
									%s,
									%s
							]
						}`, keyJWKSMarshaled, remoteEncKey)
						return newMockResponse(http.StatusOK, headers, body)
					} else {
						body := `{"error":"invalid path"}`
						return newMockResponse(http.StatusInternalServerError, headers, body)
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
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				keyJWK := &jose.JSONWebKey{Key: key.Public(), KeyID: "test key id", Algorithm: "RS256", Use: "sig"}
				keyJWKSMarshaled, err := keyJWK.MarshalJSON()
				if err != nil {
					Fail("unable to marshal generated public key")
				}

				mockClient = newMockClient(func(req *http.Request) *http.Response {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					if req.URL.Path == "/oidc/.well-known/openid-configuration" {
						return newMockResponse(http.StatusOK, headers, openidConfiguration)
					} else if req.URL.Path == "/oidc/token" {
						body := `{"error":"bad request"}`
						return newMockResponse(http.StatusBadRequest, headers, body)
					} else if req.URL.Path == "/oidc/jwks.json" {
						body := fmt.Sprintf(`{
								"keys":[
									%s,
									%s
							]
						}`, keyJWKSMarshaled, remoteEncKey)
						return newMockResponse(http.StatusOK, headers, body)
					} else {
						body := `{"error":"invalid path"}`
						return newMockResponse(http.StatusInternalServerError, headers, body)
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
	})
})

var _ = Describe("OIDCClientEncrypted tests", func() {
	var (
		mockClient *http.Client
		config     Config
	)

	Describe("OIDCClientEncrypted tests", func() {
		BeforeEach(func() {
			config = Config{
				ClientId:     "demo-ftnenc",
				ClientSecret: "mqZ-_75-f2wNsiQTONb7On4aAZ7zc218mrRVk1oufa8",
				Endpoint:     "https://example.com/oidc",
				RedirectUri:  "https://example.com/redirect",
				MleKey:       `{ "d": "Na7lzZR8gTmiJjOnrSew49tT8Qxl7-wFEJAk8_IAKmS1KidtNrNxt5GgBsy7Uksk0EXwYmbxLY7ke_yvGNtDTAaR71VWJyTDYJjiu-D-cMrRWGxLUtf0SDQtuf5_7rVNikmuUgxtaNZowstBZog-W8QIpGv7nvfOKchFK-Cf92ApWWU6DH3vN60TQtk9f8e_XLM4Yy2iBEghU58VNegb8mS9Bg-WfiG8Bf8opjj2IxlssqK98AlXPIZ-T-Xar6D9SkOVYTuracOoxSQjOEKHVCtluGQRinP3yxAQvF81ZPp2zO7LbSx2NRB4h2DzcUXSnMbY2PXgw4Sqs7QlJ7miKgrFyseRgikzZNDLv-8jhujkjRfAZ3VZFPy5-LKtG1uLf8erwwLedCqg9ClTLiXMG05uogdXIB8hYjP04ZWPNR_hQwKAEo3yFsS0SSMBOO4ANjc_uzQf7xmnKei0imDfJcufMFCvPuT_F4x6xJzi_DSLOW8s7KDFvFBTBgnTsoVHIAWDXGXM9iebLx26NwgtUcclfm2hidcsuJnS4Qyx9r-AHjxNH7uVNZP3eyjXqH4jrmweLzOGpSuLIGiXfAi7aVFISH5dD4eaq-zkxZgV-Vs8iRD8TlhYb7ETYxM71fw3Ga-rp9hAHY2_pHz3iCs3yIL08u6CGqe6udB10WmTdjk", "dp": "VYi8AKFAbw0yu5xZcf8MKwQwVSCIqZyw7gZDaz5Exz00XKHVWKlUdvqQH52e9GYW84rqdhCINcXctEnT9kfrUJRp6sg40aFWSfZNGvN0ZlwgHsuk8BKXdD0k8evgEH4iomHk5V6b8Au8ilJN3JlI3mW7ZM4aHqODfPXoNAAwHXNX24hnX3on3Y9xZvEoGZKn4WnU7rGZjcsIYphy3IGfIe0BlZYGTHnteAFjsK0ODXoGXSh2ZvhiDKO6fl57lS_h43i5gLsIOtM-T9uGFFe681h4OcM3HQNcYnwvl0RpdKXIKhVn54w7yKc1e3x6bEO5nj0ZPFwAbLWDZ0ljv_SpOw", "dq": "cqloF7Ips92f75WR2xHAuM7GmpywEWZjdiwbHqDQ79cLFbfQxO99J9kpC9kjTRE4T21OdpHOBtEIQYF8mroEHNtI9guBR1sQwMxx_DHyyJ0M1HHrzBawQr9DqqmqfHNkPCLetwv2E0sOd90CvUU6zL9p0f-Npn4-l1r7KsSAn2w5oDy4fb0ZAn4Lc4GtISYNV9SX9rpZN83WlF1oOzOWenTwiWrQneicRdM5L7HxWBs-FQQX5oi32xSf3chwy9o2po2DUD3Ess5BH-Y0lmDH6hEufwHbKRpKzWLxhZwa0BkbFL68ypbeWK-dUNdh5HCCNup0IpCgP1-_6PnQU-vw9Q", "e": "AQAB", "kty": "RSA", "n": "psPFRnGgt4wJK--20KG0M_AgL2B-J0Q4Nrd3duq0lt2kXwtD5MdAmpWpPncQgMzqVT3IyuEjFjHZRw-tv025DbK6PO4k3sZhQwWJjZGte7nKuHzJkQ7tR0ub2DOq4Sg6iBDmBFQ00wotCIfcAbgBT4WLWFu8ne9K4GUjz3vtUCALLryWJeIriJnNl7kKxo8BhbEp567PmECfill9RpPkgm3bp6s2GqAtIwWss6hYY02GPm_cssFwLl_fRBzQcFxg30i3oMgg-Xj5flewEC8sdPXdzXg9PJTLmppfKdnYtgPCTR8a2mTgy_B8vXXrkX636qk_FaT9C0QWxMg6fII_5vqRdx65uAVWqc69bm0ikSz_PgnK5flkwLRQr4D5CvZNCw7xngrEBTP42O0mjtbQJZPYzF3__pdpwqli1Ja1WNEC0EZtzi_2xs7rn07qVv2ZeQ0mObp4gs2uyflQZ-6Mv7S2MnJ00Bn7M_kl6S9a1jRHQDnCe61yfgQr8oGvfI7jaiN-8IMphzdkpK4nO4euWk8M5XQFpIorVyLT2RtIUQlA4L6GQBBuixZxI7nt2AA9ZA4J5cTukYGqT908NJ3g8HEpbWvuZ8kFOXAVi8EJqN9OFDXB5qPDfXFZ6lH7-UmYPKLOjrscX9LUSz_Onu65SVJlylHqorkK0mVOQgo7oaM", "p": "00FDBBfSFIbQYJ8yOCJ7c6ZPLmJxQ7_Fch01KdHJvKjKinb5dDtJMxgZzKwPudBajJWE4ucVMuRYRv4QMJWXov6CaLKN-SHkMFIwWMN-UJAVGT7e_iIq1_BrvFvTeFY9zshpuyFiP4lDNzPH1xX2aD0lCt42l-1rfScm1LIO0LYy1Qqma6m-aaKLAcBpr-6SM3A7-YqNVP3enZevPTz6rgZ_boKICVdR-a3vLNb5w1sP_18I3Fcb0vGCsoxuNh46DaDdSs2jkwPmIrra040vstoXHjOLzlubrrH69WqkbNtHf1DRcKgh7fzgHwuzovC6Bn142cdCmr9aLyVgExFUNw", "q": "yhYlTst5WmxYynEtYU9GBqysQnjJSh1gDKocbJv_7AHdfIMnK8tHdqEByj9DPgao76yZt1fGSN9v1B3PhVYYrhdLvtksdYjUgnu0vjtg7kHsDxwY6H4nZykxWr1tjcWHHmcUnlWU_vtkg1pES8_WJ-dtH0IYe0luPRqVqs8YYKL6He-pRbPj4YJJ6KtYgYFpSKbS3hGHDeEo_Bwz9-cP6Q6NxJwgeOZz8BtryHo4gh77RapZcpxH320Fw993xYewpAt_Bi7OqasH8-DwxMSxK-VuAjgfokxZMX2rQXLGO8xVRTVmXGbAK7deWuvlO1qgCHVxZswzI1aNyMjQ4ze_9Q", "qi": "nh4sH934RRsFA_T68m0sas6i9NaRYLOYHiK-Z4QUHxpG4lXVM1Q80srDWTYX_bGCa6R2xLTnYkICN4Y3vnUFxbfD4iBRKGdmepegF7jajbBAqCpCHDRTJUisd6MF--VOy-HPB2uIpDRw2X-g01k-AEqy7sXu1YEfh9_jEBf2JXV86mylJEqWJJT4zEtu18pq1ZV157-dLezHt1IZ9VJJldXgj1ZQza8T-15vQFfiwx1vLKZI3YiRlYVPEhCSfSqFh1C6Im9vQ8R_4kymnzDXJirzZZPJKr0FoFlJEUX8mFMCHrhqi0-OSMrCRxci_40Gtd08qo40iWjid0szYeAjfA" }`,
				Scopes:       []string{"openid", "profile", "signicat.national_id"},
			}

			mockClient = newMockClient(func(req *http.Request) *http.Response {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}

				if req.URL.Path == "/oidc/.well-known/openid-configuration" {
					return newMockResponse(http.StatusOK, headers, openidConfiguration)
				} else if req.URL.Path == "/oidc/jwks.json" {
					return newMockResponse(http.StatusOK, headers, remoteJwks)
				} else {
					body := `{"error":"invalid path"}`
					return newMockResponse(http.StatusInternalServerError, headers, body)
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
			mockClient := newMockClient(func(req *http.Request) *http.Response {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}
				return newMockResponse(http.StatusInternalServerError, headers, body)
			})

			ctx := context.Background()
			client, err := NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)

			Expect(err).NotTo(BeNil())
			Expect(client).To(BeNil())
			Expect(err.Error()).To(Equal(fmt.Sprintf("unable to initialize client: %s: %s", http.StatusText(http.StatusInternalServerError), body)))
		})
	})

})

func buildSignedJWTToken(key *rsa.PrivateKey, keyId string, claims jwt.Claims) (string, error) {
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", keyId)

	alg := jose.SignatureAlgorithm("RS256")
	signingKey := jose.SigningKey{
		Algorithm: alg,
		Key:       key,
	}
	rsaSigner, err := jose.NewSigner(signingKey, &signerOpts)
	if err != nil {
		Fail(err.Error())
	}

	return jwt.Signed(rsaSigner).Claims(claims).CompactSerialize()
}

func generateId() string {
	id := uuid.Must(uuid.NewV4())
	return id.String()
}
