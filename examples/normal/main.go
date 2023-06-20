package main

// This example implements example strong authentication flow. The credentials are
// Signicat's test credentials.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/qvik/go-oidc-mle"
)

// The payload we're expecting from the provider
type User struct {
	Subject    string `json:"sub"`
	Name       string `json:"name"`
	SSN        string `json:"signicat.national_id"`
	GivenName  string `json:"given_name"`
	Locale     string `json:"locale"`
	FamilyName string `json:"family_name"`
}

func main() {
	ctx := context.Background()
	// These credentials are taken from here: https://developer.signicat.com/documentation/authentication/protocols/openid-connect/using-the-openid-connect-protocol/
	// For real implementation you'll need your own
	config := oidc.Config{
		ClientId:     "demo-preprod",
		ClientSecret: "mqZ-_75-f2wNsiQTONb7On4aAZ7zc218mrRVk1oufa8",
		Endpoint:     "https://preprod.signicat.com/oidc",
		RedirectUri:  "http://localhost:5000/redirect",
		Scopes:       []string{"openid", "profile", "signicat.national_id"},
	}
	client := oidc.Must(oidc.NewClient(ctx, &config))

	state := generateId()
	nonce := generateId()

	authMethods := []string{
		"ftn-aktia-auth",
		"ftn-alandsbanken-auth",
		"ftn-danskebank-auth",
		"ftn-handelsbanken-auth",
		"ftn-nordea-auth",
		"ftn-omasp-auth",
		"ftn-op-auth",
		"ftn-pop-auth",
		"ftn-sp-auth",
		"ftn-spankki-auth",
		"mobiilivarmenne-ftn",
	}

	// Use one of the following authentication methods:
	//  - ftn-aktia-auth
	//  - ftn-alandsbanken-auth
	//  - ftn-danskebank-auth
	//  - ftn-handelsbanken-auth
	//  - ftn-nordea-auth
	//  - ftn-omasp-auth
	//  - ftn-op-auth
	//  - ftn-pop-auth
	//  - ftn-sp-auth
	//  - ftn-spankki-auth
	//  - mobiilivarmenne-ftn
	//
	// For example: http://localhost:5000/auth/ftn-op-auth
	http.HandleFunc("/auth/", func(w http.ResponseWriter, r *http.Request) {
		method := strings.Replace(r.URL.Path, "/auth/", "", 1)

		opts := map[string]interface{}{
			"acr_values": fmt.Sprintf("urn:signicat:oidc:method:%s", method),
			"ui_locales": "fi",
			"nonce":      nonce,
		}
		url, err := client.AuthRequestURL(state, opts)
		if err != nil {
			log.Println("unable to get authorization request uri:", err.Error())
			body := fmt.Sprintf(`{"error": "%s"}`, http.StatusText(http.StatusInternalServerError))
			http.Error(w, body, http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, url, http.StatusFound)
	})

	http.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		var userInfo User
		err := client.HandleCallback(state, nonce, r.URL.Query(), &userInfo)
		if err != nil {
			body := `{"error": "failed to exchange authorization code to token"}`
			http.Error(w, body, http.StatusInternalServerError)
			return
		}

		resp := struct {
			UserInfo User
		}{userInfo}

		data, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	})

	log.Printf("navigate to http://%s/auth/{auth_metho}, where auth_method is one of %v", "127.0.0.1:5000", authMethods)
	log.Fatal(http.ListenAndServe("127.0.0.1:5000", nil))
}

func generateId() string {
	id := uuid.Must(uuid.NewV4())
	return id.String()
}
