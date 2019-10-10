package oidc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
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

var _ = Describe("OIDCClient Tests", func() {
	var (
	//err    error
	//client *OIDCClient
	)

	BeforeSuite(func() {

	})

	JustBeforeEach(func() {
		//client.client = &MockOIDCClient{}
	})

	Describe("Must tests", func() {
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

	Describe("NewClient tests", func() {
		Describe("Initialization", func() {
			It("initializes client successfully", func() {
				config := Config{
					ClientId:     "exampleClientId",
					ClientSecret: "exampleClientSecret",
					Endpoint:     "https://preprod.signicat.com/oidc",
					RedirectUri:  "http://localhost:5000/redirect",
					Scopes:       []string{"openid", "profile", "signicat.national_id"},
				}

				mockClient := newMockClient(func(req *http.Request) *http.Response {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					body := `{"issuer":"https://preprod.signicat.com/oidc","authorization_endpoint":"https://preprod.signicat.com/oidc/authorize","token_endpoint":"https://preprod.signicat.com/oidc/token","userinfo_endpoint":"https://preprod.signicat.com/oidc/userinfo","jwks_uri":"https://preprod.signicat.com/oidc/jwks.json","scopes_supported":["openid","profile","email","address","phone","offline_access"],"response_types_supported":["code"],"response_modes_supported":["query"],"grant_types_supported":["authorization_code","refresh_token","client_credentials"],"subject_types_supported":["pairwise"],"id_token_signing_alg_values_supported":["RS256"],"id_token_encryption_alg_values_supported":["RSA1_5","RSA-OAEP","dir","A128KW","A256KW","ECDH-ES"],"id_token_encryption_enc_values_supported":["A128CBC-HS256"],"userinfo_signing_alg_values_supported":["RS256"],"userinfo_encryption_alg_values_supported":["RSA1_5","RSA-OAEP","dir","A128KW","A256KW","ECDH-ES"],"userinfo_encryption_enc_values_supported":["A128CBC-HS256"],"request_object_signing_alg_values_supported":["RS256"],"request_object_encryption_alg_values_supported":["RSA-OAEP"],"request_object_encryption_enc_values_supported":["A128CBC-HS256","A256CBC-HS512","A128GCM","A256GCM"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt"],"claim_types_supported":["normal","aggregated"],"claims_supported":["sub","name","family_name","given_name","middle_name","nickname","preferred_username","profile","picture","website","gender","birthdate","zoneinfo","locale","updated_at","email","email_verified","phone_number","phone_number_verified","address","address.formatted","address.street_address","address.locality","address.region","address.postal_code","address.country"],"service_documentation":"https://developer.signicat.com/","claims_parameter_supported":true,"request_parameter_supported":true,"request_uri_parameter_supported":false,"require_request_uri_registration":true,"op_policy_uri":"https://www.signicat.com/privacy-and-cookies/","check_session_iframe":"https://preprod.signicat.com/oidc/session/check","end_session_endpoint":"https://preprod.signicat.com/oidc/session/end","backchannel_logout_supported":true,"backchannel_logout_session_supported":false}`
					return newMockResponse(http.StatusOK, headers, body)
				})

				ctx := context.Background()
				client, err := NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)

				Expect(err).To(BeNil())
				Expect(client.provider.Endpoint().AuthURL).To(Equal("https://preprod.signicat.com/oidc/authorize"))
				Expect(client.provider.Endpoint().TokenURL).To(Equal("https://preprod.signicat.com/oidc/token"))
			})

			It("fails to initialize client if discovery fails", func() {
				config := Config{
					ClientId:     "exampleClientId",
					ClientSecret: "exampleClientSecret",
					Endpoint:     "https://preprod.signicat.com/oidc",
					RedirectUri:  "http://localhost:5000/redirect",
					Scopes:       []string{"openid", "profile", "signicat.national_id"},
				}

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
			var (
				client *OIDCClient
				config Config
			)

			JustBeforeEach(func() {
				config = Config{
					ClientId:     "exampleClientId",
					ClientSecret: "exampleClientSecret",
					Endpoint:     "https://preprod.signicat.com/oidc",
					RedirectUri:  "http://localhost:5000/redirect",
					Scopes:       []string{"openid", "profile", "signicat.national_id"},
				}

				mockClient := newMockClient(func(req *http.Request) *http.Response {
					headers := http.Header{
						"Content-Type": {"application/json"},
					}
					body := `{"issuer":"https://preprod.signicat.com/oidc","authorization_endpoint":"https://preprod.signicat.com/oidc/authorize","token_endpoint":"https://preprod.signicat.com/oidc/token","userinfo_endpoint":"https://preprod.signicat.com/oidc/userinfo","jwks_uri":"https://preprod.signicat.com/oidc/jwks.json","scopes_supported":["openid","profile","email","address","phone","offline_access"],"response_types_supported":["code"],"response_modes_supported":["query"],"grant_types_supported":["authorization_code","refresh_token","client_credentials"],"subject_types_supported":["pairwise"],"id_token_signing_alg_values_supported":["RS256"],"id_token_encryption_alg_values_supported":["RSA1_5","RSA-OAEP","dir","A128KW","A256KW","ECDH-ES"],"id_token_encryption_enc_values_supported":["A128CBC-HS256"],"userinfo_signing_alg_values_supported":["RS256"],"userinfo_encryption_alg_values_supported":["RSA1_5","RSA-OAEP","dir","A128KW","A256KW","ECDH-ES"],"userinfo_encryption_enc_values_supported":["A128CBC-HS256"],"request_object_signing_alg_values_supported":["RS256"],"request_object_encryption_alg_values_supported":["RSA-OAEP"],"request_object_encryption_enc_values_supported":["A128CBC-HS256","A256CBC-HS512","A128GCM","A256GCM"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt"],"claim_types_supported":["normal","aggregated"],"claims_supported":["sub","name","family_name","given_name","middle_name","nickname","preferred_username","profile","picture","website","gender","birthdate","zoneinfo","locale","updated_at","email","email_verified","phone_number","phone_number_verified","address","address.formatted","address.street_address","address.locality","address.region","address.postal_code","address.country"],"service_documentation":"https://developer.signicat.com/","claims_parameter_supported":true,"request_parameter_supported":true,"request_uri_parameter_supported":false,"require_request_uri_registration":true,"op_policy_uri":"https://www.signicat.com/privacy-and-cookies/","check_session_iframe":"https://preprod.signicat.com/oidc/session/check","end_session_endpoint":"https://preprod.signicat.com/oidc/session/end","backchannel_logout_supported":true,"backchannel_logout_session_supported":false}`
					return newMockResponse(http.StatusOK, headers, body)
				})

				ctx := context.Background()
				client, _ = NewClient(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)
			})

			It("returns authorization request url with correct parameters", func() {
				state := generateId()
				options := map[string]string{
					"acr_values": "urn:signicat:oidc:method:ftn-op-auth",
					"ui_locales": "fi",
				}

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
	})

	Describe("NewClientMLE tests", func() {
		It("it initializes client successfully", func() {
			mockClient := newMockClient(func(req *http.Request) *http.Response {
				headers := http.Header{
					"Content-Type": {"application/json"},
				}

				if req.URL.String() == "https://preprod.signicat.com/oidc/.well-known/openid-configuration" {
					body := `{"issuer":"https://preprod.signicat.com/oidc","authorization_endpoint":"https://preprod.signicat.com/oidc/authorize","token_endpoint":"https://preprod.signicat.com/oidc/token","userinfo_endpoint":"https://preprod.signicat.com/oidc/userinfo","jwks_uri":"https://preprod.signicat.com/oidc/jwks.json","scopes_supported":["openid","profile","email","address","phone","offline_access"],"response_types_supported":["code"],"response_modes_supported":["query"],"grant_types_supported":["authorization_code","refresh_token","client_credentials"],"subject_types_supported":["pairwise"],"id_token_signing_alg_values_supported":["RS256"],"id_token_encryption_alg_values_supported":["RSA1_5","RSA-OAEP","dir","A128KW","A256KW","ECDH-ES"],"id_token_encryption_enc_values_supported":["A128CBC-HS256"],"userinfo_signing_alg_values_supported":["RS256"],"userinfo_encryption_alg_values_supported":["RSA1_5","RSA-OAEP","dir","A128KW","A256KW","ECDH-ES"],"userinfo_encryption_enc_values_supported":["A128CBC-HS256"],"request_object_signing_alg_values_supported":["RS256"],"request_object_encryption_alg_values_supported":["RSA-OAEP"],"request_object_encryption_enc_values_supported":["A128CBC-HS256","A256CBC-HS512","A128GCM","A256GCM"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt"],"claim_types_supported":["normal","aggregated"],"claims_supported":["sub","name","family_name","given_name","middle_name","nickname","preferred_username","profile","picture","website","gender","birthdate","zoneinfo","locale","updated_at","email","email_verified","phone_number","phone_number_verified","address","address.formatted","address.street_address","address.locality","address.region","address.postal_code","address.country"],"service_documentation":"https://developer.signicat.com/","claims_parameter_supported":true,"request_parameter_supported":true,"request_uri_parameter_supported":false,"require_request_uri_registration":true,"op_policy_uri":"https://www.signicat.com/privacy-and-cookies/","check_session_iframe":"https://preprod.signicat.com/oidc/session/check","end_session_endpoint":"https://preprod.signicat.com/oidc/session/end","backchannel_logout_supported":true,"backchannel_logout_session_supported":false}`
					return newMockResponse(http.StatusOK, headers, body)
				}

				body := `{"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"any.oidc-signature-preprod.test.jwk.v.1","alg":"RS256","n":"px6mGAGqVTcf8SNBzGF5ZzMQem8QH2wXO1xXEgwQAsBCcVvlpliIj1gkPDux36DYAgdUYy1wM7VhW6FHNhT1yCA7aYteUKB9hKAai3wzQNoUXPHQlKQsWRgTboFRQrkKzPgHHIp8IwZxBFzjCp9W9gdQ_LIQyCyjxoRTR0yg21HB1SC2bh91L2K689IpS9qcb7KBjizVmGqwRCgWtA1lBOKEpgrhPeHnSLcvRWG97ePR5MfmzftWxRftWIlDaIWV_3cnn8WsXH2Qtg4cq5FGBdS30SWHTpYNRuLYfvttivR1uZmx8fnnYEfy3L7lxHbWuVbdkySofQ7yvJWX56GGJw"},{"kty":"RSA","e":"AQAB","use":"enc","kid":"any.oidc-encryption-preprod.test.jwk.v.1","alg":"RSA-OAEP","n":"ou9ZQ_e0JSMhOA3fSwzH4h9OHgS8xLbtScHUlQEq9XWRw0i5ZefGWEUCeWJgehxuRMumPdm5_csfSnJLJom3c5cEnloXB53ZFEa6qJ7AEHnSjdMxnIkzcq_4ICQg69fwTac1ZCjxhCraUs6G9LE8b9gN-EHmd8MXuLRxZUkjlgiQKb-XhfDaDA7rd7KMczyxrieZT3q5lk1fjw2V_o_jasowLo8i7s8Wa4S7BAg1ZFv2-oc8PcobbJLsAAIxg3PEn0nDIvNcs6cjjYje2_TrrXMmis2TJquQhLOHjx_yQdzQNfzxC5_GwOZPBKZR1gH1-QxlW7q8jevC2-f_-7FlHw"}]}`
				return newMockResponse(http.StatusOK, headers, body)
			})

			config := Config{
				ClientId:     "demo-ftnenc",
				ClientSecret: "mqZ-_75-f2wNsiQTONb7On4aAZ7zc218mrRVk1oufa8",
				Endpoint:     "https://preprod.signicat.com/oidc",
				RedirectUri:  "https://labs.signicat.com/redirect",
				MleKey:       `{ "d": "Na7lzZR8gTmiJjOnrSew49tT8Qxl7-wFEJAk8_IAKmS1KidtNrNxt5GgBsy7Uksk0EXwYmbxLY7ke_yvGNtDTAaR71VWJyTDYJjiu-D-cMrRWGxLUtf0SDQtuf5_7rVNikmuUgxtaNZowstBZog-W8QIpGv7nvfOKchFK-Cf92ApWWU6DH3vN60TQtk9f8e_XLM4Yy2iBEghU58VNegb8mS9Bg-WfiG8Bf8opjj2IxlssqK98AlXPIZ-T-Xar6D9SkOVYTuracOoxSQjOEKHVCtluGQRinP3yxAQvF81ZPp2zO7LbSx2NRB4h2DzcUXSnMbY2PXgw4Sqs7QlJ7miKgrFyseRgikzZNDLv-8jhujkjRfAZ3VZFPy5-LKtG1uLf8erwwLedCqg9ClTLiXMG05uogdXIB8hYjP04ZWPNR_hQwKAEo3yFsS0SSMBOO4ANjc_uzQf7xmnKei0imDfJcufMFCvPuT_F4x6xJzi_DSLOW8s7KDFvFBTBgnTsoVHIAWDXGXM9iebLx26NwgtUcclfm2hidcsuJnS4Qyx9r-AHjxNH7uVNZP3eyjXqH4jrmweLzOGpSuLIGiXfAi7aVFISH5dD4eaq-zkxZgV-Vs8iRD8TlhYb7ETYxM71fw3Ga-rp9hAHY2_pHz3iCs3yIL08u6CGqe6udB10WmTdjk", "dp": "VYi8AKFAbw0yu5xZcf8MKwQwVSCIqZyw7gZDaz5Exz00XKHVWKlUdvqQH52e9GYW84rqdhCINcXctEnT9kfrUJRp6sg40aFWSfZNGvN0ZlwgHsuk8BKXdD0k8evgEH4iomHk5V6b8Au8ilJN3JlI3mW7ZM4aHqODfPXoNAAwHXNX24hnX3on3Y9xZvEoGZKn4WnU7rGZjcsIYphy3IGfIe0BlZYGTHnteAFjsK0ODXoGXSh2ZvhiDKO6fl57lS_h43i5gLsIOtM-T9uGFFe681h4OcM3HQNcYnwvl0RpdKXIKhVn54w7yKc1e3x6bEO5nj0ZPFwAbLWDZ0ljv_SpOw", "dq": "cqloF7Ips92f75WR2xHAuM7GmpywEWZjdiwbHqDQ79cLFbfQxO99J9kpC9kjTRE4T21OdpHOBtEIQYF8mroEHNtI9guBR1sQwMxx_DHyyJ0M1HHrzBawQr9DqqmqfHNkPCLetwv2E0sOd90CvUU6zL9p0f-Npn4-l1r7KsSAn2w5oDy4fb0ZAn4Lc4GtISYNV9SX9rpZN83WlF1oOzOWenTwiWrQneicRdM5L7HxWBs-FQQX5oi32xSf3chwy9o2po2DUD3Ess5BH-Y0lmDH6hEufwHbKRpKzWLxhZwa0BkbFL68ypbeWK-dUNdh5HCCNup0IpCgP1-_6PnQU-vw9Q", "e": "AQAB", "kty": "RSA", "n": "psPFRnGgt4wJK--20KG0M_AgL2B-J0Q4Nrd3duq0lt2kXwtD5MdAmpWpPncQgMzqVT3IyuEjFjHZRw-tv025DbK6PO4k3sZhQwWJjZGte7nKuHzJkQ7tR0ub2DOq4Sg6iBDmBFQ00wotCIfcAbgBT4WLWFu8ne9K4GUjz3vtUCALLryWJeIriJnNl7kKxo8BhbEp567PmECfill9RpPkgm3bp6s2GqAtIwWss6hYY02GPm_cssFwLl_fRBzQcFxg30i3oMgg-Xj5flewEC8sdPXdzXg9PJTLmppfKdnYtgPCTR8a2mTgy_B8vXXrkX636qk_FaT9C0QWxMg6fII_5vqRdx65uAVWqc69bm0ikSz_PgnK5flkwLRQr4D5CvZNCw7xngrEBTP42O0mjtbQJZPYzF3__pdpwqli1Ja1WNEC0EZtzi_2xs7rn07qVv2ZeQ0mObp4gs2uyflQZ-6Mv7S2MnJ00Bn7M_kl6S9a1jRHQDnCe61yfgQr8oGvfI7jaiN-8IMphzdkpK4nO4euWk8M5XQFpIorVyLT2RtIUQlA4L6GQBBuixZxI7nt2AA9ZA4J5cTukYGqT908NJ3g8HEpbWvuZ8kFOXAVi8EJqN9OFDXB5qPDfXFZ6lH7-UmYPKLOjrscX9LUSz_Onu65SVJlylHqorkK0mVOQgo7oaM", "p": "00FDBBfSFIbQYJ8yOCJ7c6ZPLmJxQ7_Fch01KdHJvKjKinb5dDtJMxgZzKwPudBajJWE4ucVMuRYRv4QMJWXov6CaLKN-SHkMFIwWMN-UJAVGT7e_iIq1_BrvFvTeFY9zshpuyFiP4lDNzPH1xX2aD0lCt42l-1rfScm1LIO0LYy1Qqma6m-aaKLAcBpr-6SM3A7-YqNVP3enZevPTz6rgZ_boKICVdR-a3vLNb5w1sP_18I3Fcb0vGCsoxuNh46DaDdSs2jkwPmIrra040vstoXHjOLzlubrrH69WqkbNtHf1DRcKgh7fzgHwuzovC6Bn142cdCmr9aLyVgExFUNw", "q": "yhYlTst5WmxYynEtYU9GBqysQnjJSh1gDKocbJv_7AHdfIMnK8tHdqEByj9DPgao76yZt1fGSN9v1B3PhVYYrhdLvtksdYjUgnu0vjtg7kHsDxwY6H4nZykxWr1tjcWHHmcUnlWU_vtkg1pES8_WJ-dtH0IYe0luPRqVqs8YYKL6He-pRbPj4YJJ6KtYgYFpSKbS3hGHDeEo_Bwz9-cP6Q6NxJwgeOZz8BtryHo4gh77RapZcpxH320Fw993xYewpAt_Bi7OqasH8-DwxMSxK-VuAjgfokxZMX2rQXLGO8xVRTVmXGbAK7deWuvlO1qgCHVxZswzI1aNyMjQ4ze_9Q", "qi": "nh4sH934RRsFA_T68m0sas6i9NaRYLOYHiK-Z4QUHxpG4lXVM1Q80srDWTYX_bGCa6R2xLTnYkICN4Y3vnUFxbfD4iBRKGdmepegF7jajbBAqCpCHDRTJUisd6MF--VOy-HPB2uIpDRw2X-g01k-AEqy7sXu1YEfh9_jEBf2JXV86mylJEqWJJT4zEtu18pq1ZV157-dLezHt1IZ9VJJldXgj1ZQza8T-15vQFfiwx1vLKZI3YiRlYVPEhCSfSqFh1C6Im9vQ8R_4kymnzDXJirzZZPJKr0FoFlJEUX8mFMCHrhqi0-OSMrCRxci_40Gtd08qo40iWjid0szYeAjfA" }`,
				Scopes:       []string{"openid", "profile", "signicat.national_id"},
			}

			ctx := context.Background()
			client, err := NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)

			Expect(err).To(BeNil())
			Expect(client.provider.Endpoint().AuthURL).To(Equal("https://preprod.signicat.com/oidc/authorize"))
			Expect(client.provider.Endpoint().TokenURL).To(Equal("https://preprod.signicat.com/oidc/token"))
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

			config := Config{
				ClientId:     "exampleClientId",
				ClientSecret: "exampleClientSecret",
				Endpoint:     "https://preprod.signicat.com/oidc",
				RedirectUri:  "https://labs.signicat.com/redirect",
				MleKey:       `{ "d": "Na7lzZR8gTmiJjOnrSew49tT8Qxl7-wFEJAk8_IAKmS1KidtNrNxt5GgBsy7Uksk0EXwYmbxLY7ke_yvGNtDTAaR71VWJyTDYJjiu-D-cMrRWGxLUtf0SDQtuf5_7rVNikmuUgxtaNZowstBZog-W8QIpGv7nvfOKchFK-Cf92ApWWU6DH3vN60TQtk9f8e_XLM4Yy2iBEghU58VNegb8mS9Bg-WfiG8Bf8opjj2IxlssqK98AlXPIZ-T-Xar6D9SkOVYTuracOoxSQjOEKHVCtluGQRinP3yxAQvF81ZPp2zO7LbSx2NRB4h2DzcUXSnMbY2PXgw4Sqs7QlJ7miKgrFyseRgikzZNDLv-8jhujkjRfAZ3VZFPy5-LKtG1uLf8erwwLedCqg9ClTLiXMG05uogdXIB8hYjP04ZWPNR_hQwKAEo3yFsS0SSMBOO4ANjc_uzQf7xmnKei0imDfJcufMFCvPuT_F4x6xJzi_DSLOW8s7KDFvFBTBgnTsoVHIAWDXGXM9iebLx26NwgtUcclfm2hidcsuJnS4Qyx9r-AHjxNH7uVNZP3eyjXqH4jrmweLzOGpSuLIGiXfAi7aVFISH5dD4eaq-zkxZgV-Vs8iRD8TlhYb7ETYxM71fw3Ga-rp9hAHY2_pHz3iCs3yIL08u6CGqe6udB10WmTdjk", "dp": "VYi8AKFAbw0yu5xZcf8MKwQwVSCIqZyw7gZDaz5Exz00XKHVWKlUdvqQH52e9GYW84rqdhCINcXctEnT9kfrUJRp6sg40aFWSfZNGvN0ZlwgHsuk8BKXdD0k8evgEH4iomHk5V6b8Au8ilJN3JlI3mW7ZM4aHqODfPXoNAAwHXNX24hnX3on3Y9xZvEoGZKn4WnU7rGZjcsIYphy3IGfIe0BlZYGTHnteAFjsK0ODXoGXSh2ZvhiDKO6fl57lS_h43i5gLsIOtM-T9uGFFe681h4OcM3HQNcYnwvl0RpdKXIKhVn54w7yKc1e3x6bEO5nj0ZPFwAbLWDZ0ljv_SpOw", "dq": "cqloF7Ips92f75WR2xHAuM7GmpywEWZjdiwbHqDQ79cLFbfQxO99J9kpC9kjTRE4T21OdpHOBtEIQYF8mroEHNtI9guBR1sQwMxx_DHyyJ0M1HHrzBawQr9DqqmqfHNkPCLetwv2E0sOd90CvUU6zL9p0f-Npn4-l1r7KsSAn2w5oDy4fb0ZAn4Lc4GtISYNV9SX9rpZN83WlF1oOzOWenTwiWrQneicRdM5L7HxWBs-FQQX5oi32xSf3chwy9o2po2DUD3Ess5BH-Y0lmDH6hEufwHbKRpKzWLxhZwa0BkbFL68ypbeWK-dUNdh5HCCNup0IpCgP1-_6PnQU-vw9Q", "e": "AQAB", "kty": "RSA", "n": "psPFRnGgt4wJK--20KG0M_AgL2B-J0Q4Nrd3duq0lt2kXwtD5MdAmpWpPncQgMzqVT3IyuEjFjHZRw-tv025DbK6PO4k3sZhQwWJjZGte7nKuHzJkQ7tR0ub2DOq4Sg6iBDmBFQ00wotCIfcAbgBT4WLWFu8ne9K4GUjz3vtUCALLryWJeIriJnNl7kKxo8BhbEp567PmECfill9RpPkgm3bp6s2GqAtIwWss6hYY02GPm_cssFwLl_fRBzQcFxg30i3oMgg-Xj5flewEC8sdPXdzXg9PJTLmppfKdnYtgPCTR8a2mTgy_B8vXXrkX636qk_FaT9C0QWxMg6fII_5vqRdx65uAVWqc69bm0ikSz_PgnK5flkwLRQr4D5CvZNCw7xngrEBTP42O0mjtbQJZPYzF3__pdpwqli1Ja1WNEC0EZtzi_2xs7rn07qVv2ZeQ0mObp4gs2uyflQZ-6Mv7S2MnJ00Bn7M_kl6S9a1jRHQDnCe61yfgQr8oGvfI7jaiN-8IMphzdkpK4nO4euWk8M5XQFpIorVyLT2RtIUQlA4L6GQBBuixZxI7nt2AA9ZA4J5cTukYGqT908NJ3g8HEpbWvuZ8kFOXAVi8EJqN9OFDXB5qPDfXFZ6lH7-UmYPKLOjrscX9LUSz_Onu65SVJlylHqorkK0mVOQgo7oaM", "p": "00FDBBfSFIbQYJ8yOCJ7c6ZPLmJxQ7_Fch01KdHJvKjKinb5dDtJMxgZzKwPudBajJWE4ucVMuRYRv4QMJWXov6CaLKN-SHkMFIwWMN-UJAVGT7e_iIq1_BrvFvTeFY9zshpuyFiP4lDNzPH1xX2aD0lCt42l-1rfScm1LIO0LYy1Qqma6m-aaKLAcBpr-6SM3A7-YqNVP3enZevPTz6rgZ_boKICVdR-a3vLNb5w1sP_18I3Fcb0vGCsoxuNh46DaDdSs2jkwPmIrra040vstoXHjOLzlubrrH69WqkbNtHf1DRcKgh7fzgHwuzovC6Bn142cdCmr9aLyVgExFUNw", "q": "yhYlTst5WmxYynEtYU9GBqysQnjJSh1gDKocbJv_7AHdfIMnK8tHdqEByj9DPgao76yZt1fGSN9v1B3PhVYYrhdLvtksdYjUgnu0vjtg7kHsDxwY6H4nZykxWr1tjcWHHmcUnlWU_vtkg1pES8_WJ-dtH0IYe0luPRqVqs8YYKL6He-pRbPj4YJJ6KtYgYFpSKbS3hGHDeEo_Bwz9-cP6Q6NxJwgeOZz8BtryHo4gh77RapZcpxH320Fw993xYewpAt_Bi7OqasH8-DwxMSxK-VuAjgfokxZMX2rQXLGO8xVRTVmXGbAK7deWuvlO1qgCHVxZswzI1aNyMjQ4ze_9Q", "qi": "nh4sH934RRsFA_T68m0sas6i9NaRYLOYHiK-Z4QUHxpG4lXVM1Q80srDWTYX_bGCa6R2xLTnYkICN4Y3vnUFxbfD4iBRKGdmepegF7jajbBAqCpCHDRTJUisd6MF--VOy-HPB2uIpDRw2X-g01k-AEqy7sXu1YEfh9_jEBf2JXV86mylJEqWJJT4zEtu18pq1ZV157-dLezHt1IZ9VJJldXgj1ZQza8T-15vQFfiwx1vLKZI3YiRlYVPEhCSfSqFh1C6Im9vQ8R_4kymnzDXJirzZZPJKr0FoFlJEUX8mFMCHrhqi0-OSMrCRxci_40Gtd08qo40iWjid0szYeAjfA" }`,
				Scopes:       []string{"openid", "profile", "signicat.national_id"},
			}
			ctx := context.Background()
			client, err := NewClientMLE(context.WithValue(ctx, oauth2.HTTPClient, mockClient), &config)

			Expect(err).NotTo(BeNil())
			Expect(client).To(BeNil())
			Expect(err.Error()).To(Equal(fmt.Sprintf("unable to initialize client: %s: %s", http.StatusText(http.StatusInternalServerError), body)))
		})
	})

})
