# Go OIDC MLE

[![GoDoc](https://godoc.org/github.com/qvik/go-oidc-mle?status.svg)](https://godoc.org/github.com/qvik/go-oidc-mle)

This library wraps [oauth2](https://godoc.org/golang.org/x/oauth2) and [go-oidc](https://godoc.org/github.com/coreos/go-oidc) libraries and implements OIDC authorization code flow with an optional encrypted request object. The Finnish Transport and Communications Agency Traficom mandates message level encryption on electric identification and trust services. More information can be found from the [Regulation 72 on electronic identification and trust services](https://www.traficom.fi/en/regulations#%7B%22query%22%3A%2272%22%2C%22sort%22%3A%7B%22title%22%3A%22ASC%22%7D%2C%22limit%22%3A20%2C%22offset%22%3A0%2C%22filters%22%3A%7B%7D%7D).

- [Regulation 72 on electronic identification and trust services (pdf)](https://www.finlex.fi/data/normit/42947/M72A-2018-EN-v2.pdf)
- [Explanatory notes to Regulation 72 (pdf)](https://www.finlex.fi/data/normit/42947/M72A-MPS-EN.pdf)

## Examples

A simplified example implementation of authorization code flow using [Signicat](https://signicat.com) as a provider can be found from [the examples](https://github.com/qvik/go-oidc-mle/blob/master/examples) directory.

To run the example using MLE:
```bash
cd examples/mle
go run main.go
```

To run the non-encrypted example:
```bash
cd examples/normal
go run main.go
```

## Usage

Configuration is defined as follows. The example uses Signicat's demo account credentials and JWK. For real implementation you'll need your own credentials and key. The public key must be sent to the service provider.

```go
// These credentials are taken from here: https://github.com/signicat/OIDC-MLE/blob/master/py-ftn-example/ftn-mle-example.py
// For real implementation you'll need your own credentials and JWK.
config := oidc.Config{
    ClientId:     "demo-ftnenc",
    ClientSecret: "mqZ-_75-f2wNsiQTONb7On4aAZ7zc218mrRVk1oufa8",
    Endpoint:     "https://preprod.signicat.com/oidc",
    RedirectUri:  "https://localhost:5000/redirect",
    LocalJWK:       `{ "d": "Na7lzZR8gTmiJjOnrSew49tT8Qxl7-wFEJAk8_IAKmS1KidtNrNxt5GgBsy7Uksk0EXwYmbxLY7ke_yvGNtDTAaR71VWJyTDYJjiu-D-cMrRWGxLUtf0SDQtuf5_7rVNikmuUgxtaNZowstBZog-W8QIpGv7nvfOKchFK-Cf92ApWWU6DH3vN60TQtk9f8e_XLM4Yy2iBEghU58VNegb8mS9Bg-WfiG8Bf8opjj2IxlssqK98AlXPIZ-T-Xar6D9SkOVYTuracOoxSQjOEKHVCtluGQRinP3yxAQvF81ZPp2zO7LbSx2NRB4h2DzcUXSnMbY2PXgw4Sqs7QlJ7miKgrFyseRgikzZNDLv-8jhujkjRfAZ3VZFPy5-LKtG1uLf8erwwLedCqg9ClTLiXMG05uogdXIB8hYjP04ZWPNR_hQwKAEo3yFsS0SSMBOO4ANjc_uzQf7xmnKei0imDfJcufMFCvPuT_F4x6xJzi_DSLOW8s7KDFvFBTBgnTsoVHIAWDXGXM9iebLx26NwgtUcclfm2hidcsuJnS4Qyx9r-AHjxNH7uVNZP3eyjXqH4jrmweLzOGpSuLIGiXfAi7aVFISH5dD4eaq-zkxZgV-Vs8iRD8TlhYb7ETYxM71fw3Ga-rp9hAHY2_pHz3iCs3yIL08u6CGqe6udB10WmTdjk", "dp": "VYi8AKFAbw0yu5xZcf8MKwQwVSCIqZyw7gZDaz5Exz00XKHVWKlUdvqQH52e9GYW84rqdhCINcXctEnT9kfrUJRp6sg40aFWSfZNGvN0ZlwgHsuk8BKXdD0k8evgEH4iomHk5V6b8Au8ilJN3JlI3mW7ZM4aHqODfPXoNAAwHXNX24hnX3on3Y9xZvEoGZKn4WnU7rGZjcsIYphy3IGfIe0BlZYGTHnteAFjsK0ODXoGXSh2ZvhiDKO6fl57lS_h43i5gLsIOtM-T9uGFFe681h4OcM3HQNcYnwvl0RpdKXIKhVn54w7yKc1e3x6bEO5nj0ZPFwAbLWDZ0ljv_SpOw", "dq": "cqloF7Ips92f75WR2xHAuM7GmpywEWZjdiwbHqDQ79cLFbfQxO99J9kpC9kjTRE4T21OdpHOBtEIQYF8mroEHNtI9guBR1sQwMxx_DHyyJ0M1HHrzBawQr9DqqmqfHNkPCLetwv2E0sOd90CvUU6zL9p0f-Npn4-l1r7KsSAn2w5oDy4fb0ZAn4Lc4GtISYNV9SX9rpZN83WlF1oOzOWenTwiWrQneicRdM5L7HxWBs-FQQX5oi32xSf3chwy9o2po2DUD3Ess5BH-Y0lmDH6hEufwHbKRpKzWLxhZwa0BkbFL68ypbeWK-dUNdh5HCCNup0IpCgP1-_6PnQU-vw9Q", "e": "AQAB", "kty": "RSA", "n": "psPFRnGgt4wJK--20KG0M_AgL2B-J0Q4Nrd3duq0lt2kXwtD5MdAmpWpPncQgMzqVT3IyuEjFjHZRw-tv025DbK6PO4k3sZhQwWJjZGte7nKuHzJkQ7tR0ub2DOq4Sg6iBDmBFQ00wotCIfcAbgBT4WLWFu8ne9K4GUjz3vtUCALLryWJeIriJnNl7kKxo8BhbEp567PmECfill9RpPkgm3bp6s2GqAtIwWss6hYY02GPm_cssFwLl_fRBzQcFxg30i3oMgg-Xj5flewEC8sdPXdzXg9PJTLmppfKdnYtgPCTR8a2mTgy_B8vXXrkX636qk_FaT9C0QWxMg6fII_5vqRdx65uAVWqc69bm0ikSz_PgnK5flkwLRQr4D5CvZNCw7xngrEBTP42O0mjtbQJZPYzF3__pdpwqli1Ja1WNEC0EZtzi_2xs7rn07qVv2ZeQ0mObp4gs2uyflQZ-6Mv7S2MnJ00Bn7M_kl6S9a1jRHQDnCe61yfgQr8oGvfI7jaiN-8IMphzdkpK4nO4euWk8M5XQFpIorVyLT2RtIUQlA4L6GQBBuixZxI7nt2AA9ZA4J5cTukYGqT908NJ3g8HEpbWvuZ8kFOXAVi8EJqN9OFDXB5qPDfXFZ6lH7-UmYPKLOjrscX9LUSz_Onu65SVJlylHqorkK0mVOQgo7oaM", "p": "00FDBBfSFIbQYJ8yOCJ7c6ZPLmJxQ7_Fch01KdHJvKjKinb5dDtJMxgZzKwPudBajJWE4ucVMuRYRv4QMJWXov6CaLKN-SHkMFIwWMN-UJAVGT7e_iIq1_BrvFvTeFY9zshpuyFiP4lDNzPH1xX2aD0lCt42l-1rfScm1LIO0LYy1Qqma6m-aaKLAcBpr-6SM3A7-YqNVP3enZevPTz6rgZ_boKICVdR-a3vLNb5w1sP_18I3Fcb0vGCsoxuNh46DaDdSs2jkwPmIrra040vstoXHjOLzlubrrH69WqkbNtHf1DRcKgh7fzgHwuzovC6Bn142cdCmr9aLyVgExFUNw", "q": "yhYlTst5WmxYynEtYU9GBqysQnjJSh1gDKocbJv_7AHdfIMnK8tHdqEByj9DPgao76yZt1fGSN9v1B3PhVYYrhdLvtksdYjUgnu0vjtg7kHsDxwY6H4nZykxWr1tjcWHHmcUnlWU_vtkg1pES8_WJ-dtH0IYe0luPRqVqs8YYKL6He-pRbPj4YJJ6KtYgYFpSKbS3hGHDeEo_Bwz9-cP6Q6NxJwgeOZz8BtryHo4gh77RapZcpxH320Fw993xYewpAt_Bi7OqasH8-DwxMSxK-VuAjgfokxZMX2rQXLGO8xVRTVmXGbAK7deWuvlO1qgCHVxZswzI1aNyMjQ4ze_9Q", "qi": "nh4sH934RRsFA_T68m0sas6i9NaRYLOYHiK-Z4QUHxpG4lXVM1Q80srDWTYX_bGCa6R2xLTnYkICN4Y3vnUFxbfD4iBRKGdmepegF7jajbBAqCpCHDRTJUisd6MF--VOy-HPB2uIpDRw2X-g01k-AEqy7sXu1YEfh9_jEBf2JXV86mylJEqWJJT4zEtu18pq1ZV157-dLezHt1IZ9VJJldXgj1ZQza8T-15vQFfiwx1vLKZI3YiRlYVPEhCSfSqFh1C6Im9vQ8R_4kymnzDXJirzZZPJKr0FoFlJEUX8mFMCHrhqi0-OSMrCRxci_40Gtd08qo40iWjid0szYeAjfA" }`,
    Scopes:       []string{"openid", "profile", "signicat.national_id"},
}
```

To get started with OIDC, on must initialize the client. In this example we intialize a client that uses message level encryption with the provider.

```go
ctx := context.Background()
client := oidc.Must(oidc.NewClientMLE(ctx, &config))
```

To create authorization request, one might need to provide some addition options. The example is for Signicat and defines that ftn-op-auth authentication method shall be used and the user interface language is Finnish. The state should be something that is not easy to guess such as UUID.

```go
state := "oneTimeStateHere"
nonce := "oneTimeNonceHere"
options := map[string]string{
    "acr_values": fmt.Sprintf("urn:signicat:oidc:method:ftn-op-auth"),
    "ui_locales": "fi",
    "nonce":      nonce,
}
url, err := client.AuthRequestURL(state, options)
if err != nil {
    log.Fatal("failed to create authorization request url:", err.Error())
}
log.Printf("Authorization URL: %s\n", url)
```

The next step is to redirect the user to the authorization url. Once the user has completed the authorization process, the service provider will redirect the customer to the redirect_uri that was specified as part of the config.

In the redirect uri handler the request should be validated. Namely, error and error_description query parameters should not be present. In addition, the state should match to the one specified as part of the authorization request. If nonce was specified as part of the authorization request, the id_token should contain the same nonce unmodified. If everything checks out you can proceed to exchanging the authorization code for token. Go-oidc-mle provides a convenience method HandleCallback which validates the request, nonce and state. Alternatively you can do the same manually.

Define a type for the data you're expecting to receive from the user info endpoint of the service provider. The content depends on the scope that you specified. Once again, the example below is for the scope that we specified in the config for Signicat.
```go
type User struct {
	Subject    string `json:"sub"`
	Name       string `json:"name"`
	SSN        string `json:"signicat.national_id"`
	GivenName  string `json:"given_name"`
	Locale     string `json:"locale"`
	FamilyName string `json:"family_name"`
}
```

Exchange the authorization code for an access token and request user info.
```go
var userInfo User
err = client.HandleCallback(state, nonce, req.URL.Query(), &userInfo)
if err != nil {
    log.Fatalln("unable to handle callback:", err.Error())
}

response := struct {
    UserInfo User
}{userInfo}

data, err := json.MarshalIndent(response, "", "  ")
if err != nil {
    log.Fatal("unable to marshal user info:", err.Error())
}
log.Println(string(data))
```

Congratulations, you've now successfully received the user information you requested.

## Documentation

Documentation for the libraries go-oidc-mle uses.

- [oauth2](https://godoc.org/golang.org/x/oauth2)
- [go-oidc](https://godoc.org/github.com/coreos/go-oidc)

## Contributing

All contributions are warmly welcome, but please write tests for the changes. The existing tests have been written using [Ginkgo](https://onsi.github.io/ginkgo/) and [Gomega](http://onsi.github.io/gomega/).

To run the tests:
```bash
go test -race -coverprofile=coverage.out ./...
```

To check the coverity on browser:
```bash
go tool cover -html=coverage.out
```

One can also use Ginkgo to run the tests.
```bash
ginkgo -cover
```

## Status

[![Actions Status](https://github.com/qvik/go-oidc-mle/workflows/Tests%20on%20linux/badge.svg)](https://github.com/qvik/go-oidc-mle/actions)

[![Actions Status](https://github.com/qvik/go-oidc-mle/workflows/Tests%20on%20all%20platforms/badge.svg)](https://github.com/qvik/go-oidc-mle/actions)
