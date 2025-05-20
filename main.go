package main

import (
	"dexgate/internal/config"
	"dexgate/internal/director"
	"dexgate/internal/oidcapp"
	"dexgate/internal/templates"
	"dexgate/internal/users"
	"fmt"
	"github.com/alexedwards/scs/v2"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
)

var log *logrus.Entry

//func dumpHeader(r *http.Request) {
//	for name, values := range r.Header {
//		for _, value := range values {
//			log.Debugf("%s %s", name, value)
//		}
//	}
//}

func main() {
	config.Setup()
	log = config.Log
	log.Infof("Dexgate %s (build:%s) listening at '%s' to forward to '%s' (Logleve:%s)", config.Version, config.BuildTs, config.Conf.BindAddr, config.Conf.TargetURL, config.Conf.LogLevel)
	log.Infof("Session will expire after %s of inactivity and will not be longer than %s", config.IdleTimeout.String(), config.SessionLifetime.String())
	log.Infof("Request scopes: %s (validated:%t)", strings.Join(config.Conf.OidcConfig.Scopes, ", "), !config.Conf.OidcConfig.SkipCheckScopes)
	sessionManager := scs.New()
	sessionManager.Cookie.Name = "dg_session"
	sessionManager.IdleTimeout = config.IdleTimeout
	sessionManager.Lifetime = config.SessionLifetime

	reverseProxy := &httputil.ReverseProxy{Director: director.NewDirector(config.TargetURL)}

	oidcApp, err := oidcapp.NewOidcApp(&config.Conf.OidcConfig)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: Unable to instanciate OIDC subsystem:%v'\n", err)
		os.Exit(2)
	}
	userFilter, err := users.NewUserFilter()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: Unable to load '%s': %v\n", config.Conf.UsersConfigFile, err)
		os.Exit(2)
	}
	defer userFilter.Close()

	mux := http.NewServeMux()
	mux.Handle("/dg_logout", lougoutHandler(sessionManager))
	mux.Handle("/dg_info", infoHandler(sessionManager))
	mux.Handle("/dg_unallowed", unallowedHandler(sessionManager))
	mux.Handle("/dg_callback", callbackHandler(sessionManager, oidcApp, userFilter))
	for _, path := range config.Conf.Passthroughs {
		log.Infof("Will set passthrough for %s", path)
		mux.Handle(path, passthroughHandler(reverseProxy))
	}
	mux.Handle("/", mainHandler(sessionManager, reverseProxy, oidcApp))
	log.Fatal(http.ListenAndServe(config.Conf.BindAddr, sessionManager.LoadAndSave(mux)))
}

// Key for session object
const (
	landingURLKey  = "landingURL"
	accessTokenKey = "accessToken"
	claimKey       = "claim"
)

func passthroughHandler(reverseProxy *httputil.ReverseProxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("%s %s => Forward to target (passthrough)", r.Method, r.URL)
		reverseProxy.ServeHTTP(w, r)
	})
}

/*
 We store the token and the claim in the session, as markers for logged user.
 But, we don't handle token expiration nor renewal. We rely on the session lifecycle instead
*/

func mainHandler(sessionManager *scs.SessionManager, reverseProxy *httputil.ReverseProxy, oidcApp *oidcapp.OidcApp) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := sessionManager.GetString(r.Context(), accessTokenKey)
		if token == "" {
			// Fresh session. Must enter login process
			lurl, err := oidcApp.NewLoginURL()
			if err != nil {
				config.Log.Errorf(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
			} else {
				log.Debugf("%s %s => Not logged. Will redirect to %s", r.Method, r.URL, lurl)
				sessionManager.Put(r.Context(), landingURLKey, r.URL.String())
				http.Redirect(w, r, lurl, http.StatusSeeOther)
			}
		} else {
			log.Debugf("%s %s => Forward to target (Authenticated)", r.Method, r.URL)
			reverseProxy.ServeHTTP(w, r)
		}
	})
}

func callbackHandler(sessionManager *scs.SessionManager, oidcApp *oidcapp.OidcApp, userFilter users.UserFilter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code, errMsg := oidcApp.CheckCallbackRequest(r)
		if errMsg != "" {
			http.Error(w, errMsg, http.StatusBadRequest)
			return
		}
		tokenData, errMsg := oidcApp.HandleCallbackRequest(r, code)
		if errMsg != "" {
			http.Error(w, errMsg, http.StatusInternalServerError)
			return
		}
		log.Debugf("claims:%v", tokenData.Claims)
		logged, err := userFilter.ValidateUser(tokenData.Claims)
		if err != nil {
			log.Errorf("Unable to decode claim '%s': %v", tokenData.Claims, err)
			http.Error(w, fmt.Sprintf("Unable to decode claim '%s'", tokenData.Claims), http.StatusInternalServerError)
			return
		}
		landingURL := sessionManager.GetString(r.Context(), landingURLKey)
		if !logged {
			// We could render the unallowed template here. But we prefer to issue a redirect, to clean address bar from redirect callback url.
			http.Redirect(w, r, "dg_unallowed", http.StatusSeeOther)
		} else {
			sessionManager.Put(r.Context(), accessTokenKey, tokenData.AccessToken)
			sessionManager.Put(r.Context(), claimKey, tokenData.Claims)
			if config.Conf.TokenDisplay {
				log.Debugf("Displaying token page (landingURL:%s)", landingURL)
				templates.RenderToken(w, tokenData, landingURL)
			} else {
				log.Debugf("Redirecting to landingURL:%s)", landingURL)
				http.Redirect(w, r, landingURL, http.StatusSeeOther)
			}
		}
	})
}

func lougoutHandler(sessionManager *scs.SessionManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		landingURL := sessionManager.GetString(r.Context(), landingURLKey)
		_ = sessionManager.Destroy(r.Context())
		templates.RenderLogout(w, landingURL)
	})
}

func infoHandler(sessionManager *scs.SessionManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken := sessionManager.GetString(r.Context(), accessTokenKey)
		claims := sessionManager.GetString(r.Context(), claimKey)
		templates.RenderInfo(w, accessToken, claims)
	})
}

func unallowedHandler(sessionManager *scs.SessionManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		landingURL := sessionManager.GetString(r.Context(), landingURLKey)
		templates.RenderUnallowed(w, landingURL)
	})
}
