package oidcapp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"dexgate/internal/config"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

const DexgateAppState = "WhatANiceAuthStuff"

type OidcApp struct {
	config         *config.OidcConfig
	client         *http.Client
	provider       *oidc.Provider
	verifier       *oidc.IDTokenVerifier
	offlineAsScope bool
}

func NewOidcApp(oidcConfig *config.OidcConfig) (*OidcApp, error) {
	var err error
	app := &OidcApp{
		config: oidcConfig,
	}
	// We build a specific http.client, for
	// - Allowing some Debug on exchange
	// - Setup SSL connection (TODO)
	if oidcConfig.RootCAFile != "" {
		client, err := httpClientForRootCAs(oidcConfig.RootCAFile)
		if err != nil {
			return nil, err
		}
		app.client = client
	}
	if oidcConfig.Debug {
		if app.client == nil {
			app.client = &http.Client{
				Transport: debugTransport{http.DefaultTransport},
			}
		} else {
			app.client.Transport = debugTransport{app.client.Transport}
		}
	}
	if app.client == nil {
		app.client = http.DefaultClient
	}
	ctx := oidc.ClientContext(context.Background(), app.client)
	app.provider, err = oidc.NewProvider(ctx, oidcConfig.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to query provider %q: %v", oidcConfig.IssuerURL, err)
	}
	if oidcConfig.LoginURLOverride == "" {
		config.Log.Infof("Successfully queried provider %q", oidcConfig.IssuerURL)
	} else {
		config.Log.Infof("Successfully queried provider %q. (NB: Login URL will be overriden by '%s')", oidcConfig.IssuerURL, oidcConfig.LoginURLOverride)
	}
	app.verifier = app.provider.Verifier(&oidc.Config{ClientID: oidcConfig.ClientID})

	// Following is copied from dex/exammple/example.-app/main.go
	var s struct {
		// What scopes does a provider support?
		//
		// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
		ScopesSupported []string `json:"scopes_supported"`
	}
	if err := app.provider.Claims(&s); err != nil {
		return nil, fmt.Errorf("failed to parse provider scopes_supported: %v", err)
	}
	if len(s.ScopesSupported) == 0 {
		// scopes_supported is a "RECOMMENDED" discovery claim, not a required
		// one. If missing, assume that the provider follows the spec and has
		// an "offline_access" scope.
		app.offlineAsScope = true
	} else {
		// See if scopes_supported has the "offline_access" scope.
		app.offlineAsScope = func() bool {
			for _, scope := range s.ScopesSupported {
				if scope == oidc.ScopeOfflineAccess {
					return true
				}
			}
			return false
		}()
	}
	if !config.Conf.OidcConfig.SkipCheckScopes {
		// Check if configured scopes match the supported one.
		ssmap := make(map[string]bool)
		for _, scope := range s.ScopesSupported {
			ssmap[scope] = true
		}
		for _, scope := range config.Conf.OidcConfig.Scopes {
			if _, ok := ssmap[scope]; !ok {
				return nil, fmt.Errorf("scope '%s' is not supported by this OIDC server", scope)
			}
		}
	}
	return app, nil
}

// return an HTTP client which trusts the provided root CAs.
func httpClientForRootCAs(rootCAs string) (*http.Client, error) {
	tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
	rootCABytes, err := os.ReadFile(rootCAs)
	if err != nil {
		return nil, fmt.Errorf("failed to read root-ca: %v", err)
	}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
		return nil, fmt.Errorf("no certs found in root CA file %q", rootCAs)
	}
	config.Log.Infof("CA file '%s' loaded successfully.", rootCAs)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

func (app *OidcApp) oauth2Config(scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     app.config.ClientID,
		ClientSecret: app.config.ClientSecret,
		Endpoint:     app.provider.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  app.config.RedirectURL,
	}
}

func (app *OidcApp) hackUrl(loginUrl string) (string, error) {
	if app.config.LoginURLOverride == "" {
		return loginUrl, nil
	} else {
		loginURL, err := url.Parse(loginUrl)
		if err != nil {
			return "", fmt.Errorf("Error in parsing login URL '%s': %w", loginURL, err)
		}
		config.Log.Debugf("NewLoginURL before override: scheme:%s   host:%s requestURI:%s", loginURL.Scheme, loginURL.Host, loginURL.RequestURI())
		loginUrl = app.config.LoginURLOverride + "/" + loginURL.RequestURI()
		config.Log.Debugf("NewLoginURL after override: %s", loginUrl)
		return loginUrl, nil
	}
}

func (app *OidcApp) NewLoginURL() (string, error) {
	//scopes := []string{"openid", "profile", "email", "groups"}
	var urls string
	scopes := make([]string, len(config.Conf.OidcConfig.Scopes))
	copy(scopes, config.Conf.OidcConfig.Scopes)
	scopes = append(scopes, "openid") // This is required
	if app.offlineAsScope {
		scopes = append(scopes, "offline_access")
		urls = app.oauth2Config(scopes).AuthCodeURL(DexgateAppState)
	} else {
		urls = app.oauth2Config(scopes).AuthCodeURL(DexgateAppState, oauth2.AccessTypeOffline)
	}
	return app.hackUrl(urls)
}

func (app *OidcApp) CheckCallbackRequest(r *http.Request) (code string, errMsg string) {
	if r.Method == http.MethodGet {
		if errMsg := r.FormValue("error"); errMsg != "" {
			return "", fmt.Sprintf("%s: %s", errMsg, r.FormValue("error_description"))
		}
		code := r.FormValue("code")
		if code == "" {
			return "", fmt.Sprintf("no code in request: %q", r.Form)
		}
		if state := r.FormValue("state"); state != DexgateAppState {
			return "", fmt.Sprintf("expected state %q got %q", DexgateAppState, state)
		}
		return code, ""
	} else {
		return "", fmt.Sprintf("method not implemented: %s", r.Method)
	}
}

type TokenData struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	RedirectURL  string
	Claims       string
}

func (app *OidcApp) HandleCallbackRequest(r *http.Request, code string) (tokenData *TokenData, errMsg string) {
	ctx := oidc.ClientContext(r.Context(), app.client)
	oauth2Config := app.oauth2Config(nil)
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Sprintf("failed to get token: %v", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, "no id_token in token response"
	}
	idToken, err := app.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return nil, fmt.Sprintf("failed to verify ID token: %v", err)
	}
	accessToken, ok := token.Extra("access_token").(string)
	if !ok {
		return nil, "no access_token in token response"
	}
	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Sprintf("error decoding ID token claims: %v", err)
	}
	return &TokenData{
		IDToken:      rawIDToken,
		AccessToken:  accessToken,
		RefreshToken: token.RefreshToken,
		RedirectURL:  app.config.RedirectURL,
		Claims:       string(claims),
	}, ""
}
