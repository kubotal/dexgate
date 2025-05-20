package config

import (
	"github.com/sirupsen/logrus"
	"net/url"
	"time"
)

var logLevelByString = map[string]logrus.Level{
	"PANIC": logrus.PanicLevel,
	"FATAL": logrus.FatalLevel,
	"ERROR": logrus.ErrorLevel,
	"WARN":  logrus.WarnLevel,
	"INFO":  logrus.InfoLevel,
	"DEBUG": logrus.DebugLevel,
	"TRACE": logrus.TraceLevel,
}

// Exported globale variables
var (
	Conf            Config
	TargetURL       *url.URL
	Log             *logrus.Entry
	IdleTimeout     time.Duration
	SessionLifetime time.Duration
)

type OidcConfig struct {
	ClientID         string   `yaml:"clientID"`         // OAuth2 client ID of this application.
	ClientIDEnv      string   `yaml:"clientIDEnv"`      // An environment variable for OAuth2 client ID of this application.
	ClientSecret     string   `yaml:"clientSecret"`     // "OAuth2 client secret of this application."
	ClientSecretEnv  string   `yaml:"clientSecretEnv"`  // An environment variable for "OAuth2 client secret of this application."
	IssuerURL        string   `yaml:"issuerURL"`        // URL of the OpenID Connect issuer.
	RedirectURL      string   `yaml:"redirectURL"`      // Callback URL for OAuth2 responses. Domain must be same as initial call, for cookies to be shared;
	Scopes           []string `yaml:"scopes"`           // The scopes we will request from the OIDC server. Default: "profile"
	RootCAFile       string   `yaml:"rootCAFile"`       // The root CA file for validation of IssuerURL
	LoginURLOverride string   `yaml:"loginURLOverride"` // Allow overriding of scheme and host part of the login URL provided by the OIDC server
	Debug            bool     `yaml:"debug"`            // Print all request and responses from the OpenID Connect issuer.
	SkipCheckScopes  bool     `yaml:"skipCheckScopes"`  // If false, dexgate will ensure requested scopes are managed by the OIDC provider.
}

type SessionConfig struct {
	IdleTimeout string `yaml:"idleTimeout"` // The maximum length of time a session can be inactive before being expired
	Lifetime    string `yaml:"lifetime"`    // The absolute maximum length of time that a session is valid.
}

type UsersConfigMap struct {
	Namespace     string `yaml:"namespace"`     // If empty lookup current namespace. Used in out-of-cluster mode
	ConfigMapName string `yaml:"configMapName"` // Mandatory. If "", then will use UserConfigFile
	ConfigMapKey  string `yaml:"configMapKey"`  // Default to 'users.yml'
}

type Config struct {
	configFolder    string
	LogLevel        string         `yaml:"logLevel"`        // INFO,DEBUG, ....
	LogMode         string         `yaml:"logMode"`         // Log output format: 'dev' or 'json'
	BindAddr        string         `yaml:"bindAddr"`        // The address to listen on. (default to :9001)
	TargetURL       string         `yaml:"targetURL"`       // The URL to forward all requests
	OidcConfig      OidcConfig     `yaml:"oidc"`            // OIDC client config
	Passthroughs    []string       `yaml:"passthroughs"`    // Paths pattern to forward without authentication (See http.ServeMux for path definition)
	TokenDisplay    bool           `yaml:"tokenDisplay"`    // Display an intermediate token page after login (Debugging only)
	SessionConfig   SessionConfig  `yaml:"sessionConfig"`   // Web session parameters
	UsersConfigFile string         `yaml:"usersConfigFile"` // File hosting allowed users/groups
	UsersConfigMap  UsersConfigMap `yaml:"usersConfigMap"`  //
}
