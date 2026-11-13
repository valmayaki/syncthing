// Copyright (C) 2026 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package api

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syncthing/syncthing/lib/config"
)

const (
	testIssuer   = "https://auth.example.test/application/o/homelab/"
	testAudience = "homelab-client"
)

var b64 = base64.RawURLEncoding

type testIdP struct {
	rsaKey  *rsa.PrivateKey
	ecKey   *ecdsa.PrivateKey
	fetches atomic.Int32
	server  *httptest.Server
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idp := &testIdP{rsaKey: rsaKey, ecKey: ecKey}
	idp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		idp.fetches.Add(1)
		ecPub, _ := ecKey.PublicKey.Bytes() // 0x04 || X || Y
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": "rsa-1", "use": "sig", "alg": "RS256",
				"n": b64.EncodeToString(rsaKey.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes())},
			{"kty": "EC", "kid": "ec-1", "use": "sig", "crv": "P-256",
				"x": b64.EncodeToString(ecPub[1:33]), "y": b64.EncodeToString(ecPub[33:])},
		}})
	}))
	t.Cleanup(idp.server.Close)
	return idp
}

func validClaims() map[string]any {
	now := time.Now().Unix()
	return map[string]any{
		"iss": testIssuer, "aud": testAudience, "exp": now + 300, "iat": now,
		"preferred_username": "alice",
	}
}

func (idp *testIdP) token(t *testing.T, alg, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signed := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signed))
	var sig []byte
	var err error
	switch alg {
	case "RS256":
		sig, err = rsa.SignPKCS1v15(rand.Reader, idp.rsaKey, crypto.SHA256, digest[:])
	case "ES256":
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, idp.ecKey, digest[:])
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case "HS256":
		// Forgery attempt: HMAC keyed with the public modulus.
		mac := hmac.New(sha256.New, idp.rsaKey.N.Bytes())
		mac.Write([]byte(signed))
		sig = mac.Sum(nil)
	case "none":
	}
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + b64.EncodeToString(sig)
}

func (idp *testIdP) authenticator(t *testing.T, mutate func(*config.GUIProxyAuthConfiguration)) *proxyAuthenticator {
	t.Helper()
	cfg := config.GUIProxyAuthConfiguration{
		Mode:         config.ProxyAuthModeJWT,
		JWKSURL:      idp.server.URL,
		Issuer:       testIssuer,
		Audience:     testAudience,
		AllowedUsers: "alice",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := newProxyAuthenticator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func jwtRequest(token string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/rest/system/status", nil)
	r.RemoteAddr = "127.0.0.1:4711"
	if token != "" {
		r.Header.Set("X-Authentik-Jwt", token)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestProxyJWTAccepts(t *testing.T) {
	idp := newTestIdP(t)
	p := idp.authenticator(t, nil)
	for _, alg := range []struct{ alg, kid string }{{"RS256", "rsa-1"}, {"ES256", "ec-1"}} {
		user, ok, err := p.authenticate(jwtRequest(idp.token(t, alg.alg, alg.kid, validClaims()), nil))
		if !ok || err != nil || user != "alice" {
			t.Errorf("%s: user=%q ok=%v err=%v", alg.alg, user, ok, err)
		}
	}
}

func TestProxyJWTRejects(t *testing.T) {
	idp := newTestIdP(t)
	p := idp.authenticator(t, nil)
	with := func(k string, v any) map[string]any { c := validClaims(); c[k] = v; return c }
	without := func(k string) map[string]any { c := validClaims(); delete(c, k); return c }

	cases := map[string]string{
		"expired":          idp.token(t, "RS256", "rsa-1", with("exp", time.Now().Add(-5*time.Minute).Unix())),
		"not yet valid":    idp.token(t, "RS256", "rsa-1", with("nbf", time.Now().Add(5*time.Minute).Unix())),
		"no exp":           idp.token(t, "RS256", "rsa-1", without("exp")),
		"wrong issuer":     idp.token(t, "RS256", "rsa-1", with("iss", "https://evil.example.test/")),
		"wrong audience":   idp.token(t, "RS256", "rsa-1", with("aud", "other-app")),
		"user not allowed": idp.token(t, "RS256", "rsa-1", with("preferred_username", "mallory")),
		"no username":      idp.token(t, "RS256", "rsa-1", without("preferred_username")),
		"alg none":         idp.token(t, "none", "rsa-1", validClaims()),
		"alg HS256":        idp.token(t, "HS256", "rsa-1", validClaims()),
		"alg/key mismatch": idp.token(t, "ES256", "rsa-1", validClaims()),
		"unknown kid":      idp.token(t, "RS256", "nope", validClaims()),
		"malformed":        "not.a.jwt.at-all",
	}
	tampered := idp.token(t, "RS256", "rsa-1", validClaims())
	cases["tampered payload"] = tampered[:len(tampered)/2] + "x" + tampered[len(tampered)/2+1:]

	for name, token := range cases {
		user, ok, err := p.authenticate(jwtRequest(token, nil))
		if ok || err == nil {
			t.Errorf("%s: accepted (user=%q ok=%v err=%v)", name, user, ok, err)
		}
	}
}

func TestProxyJWTAudienceList(t *testing.T) {
	idp := newTestIdP(t)
	c := validClaims()
	c["aud"] = []any{"other", testAudience}
	if _, ok, err := idp.authenticator(t, nil).authenticate(jwtRequest(idp.token(t, "RS256", "rsa-1", c), nil)); !ok {
		t.Fatalf("aud list containing the audience must be accepted: %v", err)
	}
}

func TestProxyJWTWithoutTokenFallsThrough(t *testing.T) {
	idp := newTestIdP(t)
	_, ok, err := idp.authenticator(t, nil).authenticate(jwtRequest("", nil))
	if ok || err != nil {
		t.Fatalf("no token must leave other auth methods to decide: ok=%v err=%v", ok, err)
	}
}

func TestProxyJWTUserHeaderMustMatch(t *testing.T) {
	idp := newTestIdP(t)
	p := idp.authenticator(t, func(c *config.GUIProxyAuthConfiguration) { c.UserHeader = "X-Authentik-Username" })
	token := idp.token(t, "RS256", "rsa-1", validClaims())

	if _, ok, _ := p.authenticate(jwtRequest(token, map[string]string{"X-Authentik-Username": "alice"})); !ok {
		t.Error("matching user header must be accepted")
	}
	if _, ok, err := p.authenticate(jwtRequest(token, map[string]string{"X-Authentik-Username": "bob"})); ok || err == nil {
		t.Error("user header differing from the JWT must be rejected")
	}
}

func TestProxyJWTTrustedProxyRestriction(t *testing.T) {
	idp := newTestIdP(t)
	p := idp.authenticator(t, func(c *config.GUIProxyAuthConfiguration) { c.TrustedProxies = "10.0.0.0/8" })
	r := jwtRequest(idp.token(t, "RS256", "rsa-1", validClaims()), nil)
	if _, ok, err := p.authenticate(r); ok || err == nil {
		t.Fatal("a valid JWT from outside trustedProxies must be rejected")
	}
}

func TestProxyJWTRequiresIssuerAndAudience(t *testing.T) {
	for _, cfg := range []config.GUIProxyAuthConfiguration{
		{Mode: config.ProxyAuthModeJWT, JWKSURL: "http://x", Audience: "a"},
		{Mode: config.ProxyAuthModeJWT, JWKSURL: "http://x", Issuer: "i"},
		{Mode: config.ProxyAuthModeJWT, Issuer: "i", Audience: "a"},
	} {
		if _, err := newProxyAuthenticator(cfg); err == nil {
			t.Errorf("config %+v must be rejected", cfg)
		}
	}
}

func TestProxyJWKSRefetchIsRateLimited(t *testing.T) {
	idp := newTestIdP(t)
	p := idp.authenticator(t, nil)
	good := idp.token(t, "RS256", "rsa-1", validClaims())
	if _, ok, _ := p.authenticate(jwtRequest(good, nil)); !ok {
		t.Fatal("valid token rejected")
	}
	unknown := idp.token(t, "RS256", "rotated", validClaims())
	for range 20 {
		_, _, _ = p.authenticate(jwtRequest(unknown, nil))
	}
	if n := idp.fetches.Load(); n != 1 {
		t.Fatalf("unknown kids must not hammer the JWKS endpoint: %d fetches", n)
	}
}

func TestProxyAuthMiddlewareCreatesNoSession(t *testing.T) {
	idp := newTestIdP(t)
	reached := 0
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ })
	m := &basicAuthAndSessionMiddleware{
		tokenCookieManager: &tokenCookieManager{shortID: "TEST"},
		proxyAuth:          idp.authenticator(t, nil),
		guiCfg:             guiCfg,
		next:               next,
	}

	w := httptest.NewRecorder()
	m.ServeHTTP(w, jwtRequest(idp.token(t, "RS256", "rsa-1", validClaims()), nil))
	if reached != 1 || w.Code != http.StatusOK {
		t.Fatalf("valid JWT: reached=%d code=%d", reached, w.Code)
	}
	if cookies := w.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("proxy auth must not create a session, got cookies %v", cookies)
	}

	w = httptest.NewRecorder()
	m.ServeHTTP(w, jwtRequest(idp.token(t, "RS256", "rsa-1", map[string]any{"iss": "x"}), nil))
	if reached != 1 || w.Code != http.StatusForbidden {
		t.Fatalf("invalid JWT must be forbidden: reached=%d code=%d", reached, w.Code)
	}
}
