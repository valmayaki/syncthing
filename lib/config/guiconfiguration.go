// Copyright (C) 2014 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import (
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/syncthing/syncthing/lib/rand"
)

type GUIConfiguration struct {
	Enabled                   bool                      `json:"enabled" xml:"enabled,attr" default:"true"`
	RawAddress                string                    `json:"address" xml:"address" default:"127.0.0.1:8384"`
	RawUnixSocketPermissions  string                    `json:"unixSocketPermissions" xml:"unixSocketPermissions,omitempty"`
	User                      string                    `json:"user" xml:"user,omitempty"`
	Password                  string                    `json:"password" xml:"password,omitempty"`
	AuthMode                  AuthMode                  `json:"authMode" xml:"authMode,omitempty"`
	MetricsWithoutAuth        bool                      `json:"metricsWithoutAuth" xml:"metricsWithoutAuth" default:"false"`
	RawUseTLS                 bool                      `json:"useTLS" xml:"tls,attr"`
	APIKey                    string                    `json:"apiKey" xml:"apikey,omitempty"`
	InsecureAdminAccess       bool                      `json:"insecureAdminAccess" xml:"insecureAdminAccess,omitempty"`
	Theme                     string                    `json:"theme" xml:"theme" default:"default"`
	InsecureSkipHostCheck     bool                      `json:"insecureSkipHostcheck" xml:"insecureSkipHostcheck,omitempty"`
	InsecureAllowFrameLoading bool                      `json:"insecureAllowFrameLoading" xml:"insecureAllowFrameLoading,omitempty"`
	SendBasicAuthPrompt       bool                      `json:"sendBasicAuthPrompt" xml:"sendBasicAuthPrompt,attr"`
	SessionCookieDurationS    int                       `json:"sessionCookieDurationS" xml:"sessionCookieDurationS,omitempty" default:"604800"`
	SessionCookiePath         string                    `json:"sessionCookiePath" xml:"sessionCookiePath,omitempty" default:"/"`
	ProxyAuth                 GUIProxyAuthConfiguration `json:"proxyAuth" xml:"proxyAuth"`
}

// Proxy authentication modes. With ProxyAuthModeHeader the GUI trusts a
// username header set by a reverse proxy at a trusted address. With
// ProxyAuthModeJWT it verifies a signed JWT (for example authentik's
// X-Authentik-Jwt) against a JWKS and takes the username from a claim.
const (
	ProxyAuthModeOff    = ""
	ProxyAuthModeHeader = "header"
	ProxyAuthModeJWT    = "jwt"
)

// GUIProxyAuthConfiguration lets a reverse proxy that already authenticated
// the user sign them in to the GUI. All fields are strings or integers so
// GUIConfiguration stays comparable; lists are comma separated.
type GUIProxyAuthConfiguration struct {
	Mode string `json:"mode" xml:"mode,omitempty"`
	// Comma-separated IPs or CIDRs the proxy connects from. Required in
	// header mode; optional extra restriction in JWT mode.
	TrustedProxies string `json:"trustedProxies" xml:"trustedProxies,omitempty"`
	// Header with the username. In JWT mode it is optional and, when the
	// request carries it, must equal the username claim.
	UserHeader string `json:"userHeader" xml:"userHeader,omitempty" default:"Remote-User"`
	// Comma-separated usernames allowed in. Empty allows any user the
	// proxy authenticated.
	AllowedUsers string `json:"allowedUsers" xml:"allowedUsers,omitempty"`
	// JWT mode settings.
	JWTHeader     string `json:"jwtHeader" xml:"jwtHeader,omitempty" default:"X-Authentik-Jwt"`
	JWKSURL       string `json:"jwksURL" xml:"jwksURL,omitempty"`
	Issuer        string `json:"issuer" xml:"issuer,omitempty"`
	Audience      string `json:"audience" xml:"audience,omitempty"`
	UsernameClaim string `json:"usernameClaim" xml:"usernameClaim,omitempty" default:"preferred_username"`
	LeewayS       int    `json:"leewayS" xml:"leewayS,omitempty" default:"30"`
}

// Enabled reports whether a proxy authentication mode is configured.
func (c GUIProxyAuthConfiguration) Enabled() bool {
	return c.Mode == ProxyAuthModeHeader || c.Mode == ProxyAuthModeJWT
}

// SplitList splits a comma-separated configuration value, dropping blanks.
func SplitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (c GUIConfiguration) IsAuthEnabled() bool {
	// This function should match isAuthEnabled() in syncthingController.js
	return c.AuthMode == AuthModeLDAP || (len(c.User) > 0 && len(c.Password) > 0) || c.ProxyAuth.Enabled()
}

func (GUIConfiguration) IsOverridden() bool {
	return os.Getenv("STGUIADDRESS") != ""
}

func (c GUIConfiguration) Address() string {
	if override := os.Getenv("STGUIADDRESS"); override != "" {
		// This value may be of the form "scheme://address:port" or just
		// "address:port". We need to chop off the scheme. We try to parse it as
		// an URL if it contains a slash. If that fails, return it as is and let
		// some other error handling handle it.

		if strings.Contains(override, "/") {
			url, err := url.Parse(override)
			if err != nil {
				return override
			}
			if strings.HasPrefix(url.Scheme, "unix") {
				return url.Path
			}
			return url.Host
		}

		return override
	}

	return c.RawAddress
}

func (c GUIConfiguration) UnixSocketPermissions() os.FileMode {
	perm, err := strconv.ParseUint(c.RawUnixSocketPermissions, 8, 32)
	if err != nil {
		// ignore incorrectly formatted permissions
		return 0
	}
	return os.FileMode(perm) & os.ModePerm
}

func (c GUIConfiguration) Network() string {
	if override := os.Getenv("STGUIADDRESS"); override != "" {
		url, err := url.Parse(override)
		if err == nil && strings.HasPrefix(url.Scheme, "unix") {
			return "unix"
		}
		return "tcp"
	}
	if strings.HasPrefix(c.RawAddress, "/") {
		return "unix"
	}
	return "tcp"
}

func (c GUIConfiguration) UseTLS() bool {
	if override := os.Getenv("STGUIADDRESS"); override != "" {
		return strings.HasPrefix(override, "https:") || strings.HasPrefix(override, "unixs:")
	}
	return c.RawUseTLS
}

func (c GUIConfiguration) URL() string {
	if c.Network() == "unix" {
		if c.UseTLS() {
			return "unixs://" + c.Address()
		}
		return "unix://" + c.Address()
	}

	u := url.URL{
		Scheme: "http",
		Host:   c.Address(),
		Path:   "/",
	}

	if c.UseTLS() {
		u.Scheme = "https"
	}

	if strings.HasPrefix(u.Host, ":") {
		// Empty host, i.e. ":port", use IPv4 localhost
		u.Host = "127.0.0.1" + u.Host
	} else if strings.HasPrefix(u.Host, "0.0.0.0:") {
		// IPv4 all zeroes host, convert to IPv4 localhost
		u.Host = "127.0.0.1" + u.Host[7:]
	} else if strings.HasPrefix(u.Host, "[::]:") {
		// IPv6 all zeroes host, convert to IPv6 localhost
		u.Host = "[::1]" + u.Host[4:]
	}

	return u.String()
}

// matches a bcrypt hash and not too much else
var bcryptExpr = regexp.MustCompile(`^\$2[aby]\$\d+\$.{50,}`)

// SetPassword takes a bcrypt hash or a plaintext password and stores it.
// Plaintext passwords are hashed. Returns an error if the password is not
// valid.
func (c *GUIConfiguration) SetPassword(password string) error {
	if bcryptExpr.MatchString(password) {
		// Already hashed
		c.Password = password
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	c.Password = string(hash)
	return nil
}

// CompareHashedPassword returns nil when the given plaintext password matches the stored hash.
func (c GUIConfiguration) CompareHashedPassword(password string) error {
	configPasswordBytes := []byte(c.Password)
	passwordBytes := []byte(password)
	return bcrypt.CompareHashAndPassword(configPasswordBytes, passwordBytes)
}

// IsValidAPIKey returns true when the given API key is valid, including both
// the value in config and any overrides
func (c GUIConfiguration) IsValidAPIKey(apiKey string) bool {
	switch apiKey {
	case "":
		return false

	case c.APIKey, os.Getenv("STGUIAPIKEY"):
		return true

	default:
		return false
	}
}

func (c *GUIConfiguration) prepare() {
	if c.APIKey == "" {
		c.APIKey = rand.String(32)
	}
	if path := strings.TrimSpace(c.SessionCookiePath); path != "" {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		c.SessionCookiePath = path
	}
}

func (c GUIConfiguration) Copy() GUIConfiguration {
	return c
}
