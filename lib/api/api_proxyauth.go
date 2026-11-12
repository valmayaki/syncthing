// Copyright (C) 2026 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package api

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/syncthing/syncthing/internal/slogutil"
	"github.com/syncthing/syncthing/lib/config"
)

const (
	defaultProxyUserHeader    = "Remote-User"
	defaultProxyJWTHeader     = "X-Authentik-Jwt"
	defaultProxyUsernameClaim = "preferred_username"
	defaultProxyLeeway        = 30 * time.Second
	jwksRefreshInterval       = time.Hour
	jwksMinRefetchInterval    = 30 * time.Second
	jwksFetchTimeout          = 10 * time.Second
	maxJWKSSize               = 1 << 20
	maxJWTSize                = 16 << 10
)

// proxyAuthenticator signs a user in from headers set by a reverse proxy
// that already authenticated them. It never accepts a request on its own
// say-so: header mode requires a trusted proxy address, JWT mode a valid
// signature from the configured JWKS.
type proxyAuthenticator struct {
	mode          string
	trusted       []netip.Prefix
	userHeader    string
	allowedUsers  []string
	jwtHeader     string
	usernameClaim string
	issuer        string
	audience      string
	leeway        time.Duration
	jwks          *jwksCache
}

func newProxyAuthenticator(cfg config.GUIProxyAuthConfiguration) (*proxyAuthenticator, error) {
	if !cfg.Enabled() {
		return nil, nil
	}
	p := &proxyAuthenticator{
		mode:          cfg.Mode,
		userHeader:    orDefault(cfg.UserHeader, defaultProxyUserHeader),
		allowedUsers:  config.SplitList(cfg.AllowedUsers),
		jwtHeader:     orDefault(cfg.JWTHeader, defaultProxyJWTHeader),
		usernameClaim: orDefault(cfg.UsernameClaim, defaultProxyUsernameClaim),
		issuer:        cfg.Issuer,
		audience:      cfg.Audience,
		leeway:        defaultProxyLeeway,
	}
	if cfg.LeewayS > 0 {
		p.leeway = time.Duration(cfg.LeewayS) * time.Second
	}
	for _, entry := range config.SplitList(cfg.TrustedProxies) {
		prefix, err := parsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("proxy auth: trusted proxy %q: %w", entry, err)
		}
		p.trusted = append(p.trusted, prefix)
	}
	switch p.mode {
	case config.ProxyAuthModeHeader:
		if len(p.trusted) == 0 {
			return nil, errors.New("proxy auth: header mode needs trustedProxies")
		}
	case config.ProxyAuthModeJWT:
		if cfg.JWKSURL == "" {
			return nil, errors.New("proxy auth: jwt mode needs jwksURL")
		}
		if p.issuer == "" || p.audience == "" {
			return nil, errors.New("proxy auth: jwt mode needs issuer and audience")
		}
		p.jwks = newJWKSCache(cfg.JWKSURL)
	}
	return p, nil
}

func orDefault(v, def string) string {
	if v = strings.TrimSpace(v); v != "" {
		return v
	}
	return def
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		return prefix.Masked(), err
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()), nil
}

// fromTrustedProxy reports whether the TCP peer (not X-Forwarded-For) is a
// trusted proxy. With no trusted proxies configured it returns true, which
// only JWT mode allows.
func (p *proxyAuthenticator) fromTrustedProxy(r *http.Request) bool {
	if len(p.trusted) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return slices.ContainsFunc(p.trusted, func(prefix netip.Prefix) bool {
		return prefix.Contains(addr)
	})
}

func (p *proxyAuthenticator) userAllowed(username string) bool {
	return len(p.allowedUsers) == 0 || slices.Contains(p.allowedUsers, username)
}

// authenticate returns the proxy-asserted username. ok is false when the
// request carries no proxy identity at all (so other methods may apply);
// err is set when it carries one that must be rejected.
func (p *proxyAuthenticator) authenticate(r *http.Request) (username string, ok bool, err error) {
	switch p.mode {
	case config.ProxyAuthModeHeader:
		username = strings.TrimSpace(r.Header.Get(p.userHeader))
		if username == "" {
			return "", false, nil
		}
		if !p.fromTrustedProxy(r) {
			return "", false, errors.New("user header from untrusted address")
		}
	case config.ProxyAuthModeJWT:
		token := strings.TrimSpace(r.Header.Get(p.jwtHeader))
		if token == "" {
			return "", false, nil
		}
		if !p.fromTrustedProxy(r) {
			return "", false, errors.New("JWT from untrusted address")
		}
		username, err = p.verifyJWT(r.Context(), token)
		if err != nil {
			return "", false, err
		}
		if header := strings.TrimSpace(r.Header.Get(p.userHeader)); header != "" && header != username {
			return "", false, errors.New("user header does not match the JWT")
		}
	default:
		return "", false, nil
	}
	if !p.userAllowed(username) {
		return "", false, fmt.Errorf("user %q is not allowed", username)
	}
	return username, true, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

func (p *proxyAuthenticator) verifyJWT(ctx context.Context, token string) (string, error) {
	if len(token) > maxJWTSize {
		return "", errors.New("JWT too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed JWT")
	}
	var hdr jwtHeader
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return "", fmt.Errorf("JWT header: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("JWT signature: %w", err)
	}
	key, err := p.jwks.key(ctx, hdr.Kid)
	if err != nil {
		return "", err
	}
	if err := verifySignature(hdr.Alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return "", err
	}

	var claims map[string]any
	if err := decodeSegment(parts[1], &claims); err != nil {
		return "", fmt.Errorf("JWT claims: %w", err)
	}
	now := time.Now()
	exp, ok := numericClaim(claims, "exp")
	if !ok {
		return "", errors.New("JWT has no exp")
	}
	if now.After(exp.Add(p.leeway)) {
		return "", errors.New("JWT expired")
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok && now.Add(p.leeway).Before(nbf) {
		return "", errors.New("JWT not valid yet")
	}
	if iss, _ := claims["iss"].(string); iss != p.issuer {
		return "", fmt.Errorf("JWT issuer %q not accepted", iss)
	}
	if !audienceContains(claims["aud"], p.audience) {
		return "", errors.New("JWT audience not accepted")
	}
	username, _ := claims[p.usernameClaim].(string)
	if username = strings.TrimSpace(username); username == "" {
		return "", fmt.Errorf("JWT has no %s claim", p.usernameClaim)
	}
	return username, nil
}

func decodeSegment(seg string, v any) error {
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func numericClaim(claims map[string]any, name string) (time.Time, bool) {
	v, ok := claims[name].(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(v), 0), true
}

func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		return slices.ContainsFunc(v, func(item any) bool {
			s, _ := item.(string)
			return s == want
		})
	}
	return false
}

// verifySignature accepts only asymmetric algorithms, so a JWKS holding
// public keys can never be used to forge tokens (no "none", no HS*).
func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) error {
	var h hash.Hash
	var ch crypto.Hash
	switch alg {
	case "RS256", "ES256", "PS256":
		h, ch = sha256.New(), crypto.SHA256
	case "RS384", "ES384", "PS384":
		h, ch = sha512.New384(), crypto.SHA384
	case "RS512", "ES512", "PS512":
		h, ch = sha512.New(), crypto.SHA512
	default:
		return fmt.Errorf("JWT algorithm %q not accepted", alg)
	}
	h.Write(signed)
	digest := h.Sum(nil)

	switch k := key.(type) {
	case *rsa.PublicKey:
		switch alg[:2] {
		case "RS":
			return rsa.VerifyPKCS1v15(k, ch, digest, sig)
		case "PS":
			return rsa.VerifyPSS(k, ch, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
	case *ecdsa.PublicKey:
		if alg[:2] != "ES" {
			break
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return errors.New("bad ECDSA signature length")
		}
		rr := new(big.Int).SetBytes(sig[:size])
		ss := new(big.Int).SetBytes(sig[size:])
		if ecdsa.Verify(k, digest, rr, ss) {
			return nil
		}
		return errors.New("bad ECDSA signature")
	}
	return fmt.Errorf("JWT algorithm %q does not match the key type", alg)
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	dec := base64.RawURLEncoding
	switch k.Kty {
	case "RSA":
		n, err := dec.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		e, err := dec.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		exp := new(big.Int).SetBytes(e)
		if !exp.IsInt64() || exp.Int64() < 3 || exp.Int64() > 1<<31-1 {
			return nil, errors.New("bad RSA exponent")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}
		if pub.N.BitLen() < 2048 {
			return nil, errors.New("RSA key shorter than 2048 bits")
		}
		return pub, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err := dec.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		y, err := dec.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		// Uncompressed point encoding, validated by ecdh.
		size := (curve.Params().BitSize + 7) / 8
		if len(x) > size || len(y) > size {
			return nil, errors.New("bad EC point")
		}
		pt := make([]byte, 1+2*size)
		pt[0] = 4
		copy(pt[1+size-len(x):1+size], x)
		copy(pt[1+2*size-len(y):], y)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, pt)
		if err != nil {
			return nil, err
		}
		return pub, nil
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

// jwksCache fetches the JWKS lazily, refreshes it hourly and refetches at
// most every 30 s when a token names an unknown key (key rotation).
type jwksCache struct {
	url    string
	client *http.Client

	mut       sync.Mutex
	keys      map[string]crypto.PublicKey
	fetched   time.Time
	attempted time.Time
}

func newJWKSCache(url string) *jwksCache {
	return &jwksCache{url: url, client: &http.Client{Timeout: jwksFetchTimeout}}
}

func (c *jwksCache) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	c.mut.Lock()
	defer c.mut.Unlock()

	now := time.Now()
	stale := now.Sub(c.fetched) > jwksRefreshInterval
	_, known := c.lookup(kid)
	if (stale || !known) && now.Sub(c.attempted) > jwksMinRefetchInterval {
		c.attempted = now
		if err := c.fetch(ctx); err != nil {
			slog.Warn("Failed to fetch proxy auth JWKS", slog.String("url", c.url), slogutil.Error(err))
		}
	}
	if key, ok := c.lookup(kid); ok {
		return key, nil
	}
	return nil, fmt.Errorf("no JWKS key for kid %q", kid)
}

// lookup finds a key by kid; a token without kid matches a single-key set.
func (c *jwksCache) lookup(kid string) (crypto.PublicKey, bool) {
	if kid == "" && len(c.keys) == 1 {
		for _, key := range c.keys {
			return key, true
		}
	}
	key, ok := c.keys[kid]
	return key, ok
}

func (c *jwksCache) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS answered %s", resp.Status)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSSize)).Decode(&set); err != nil {
		return err
	}
	keys := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			slog.Warn("Skipping proxy auth JWKS key", slog.String("kid", k.Kid), slogutil.Error(err))
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("JWKS has no usable signing keys")
	}
	c.keys = keys
	c.fetched = time.Now()
	return nil
}
