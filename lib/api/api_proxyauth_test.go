package api

import (
	"net/http/httptest"
	"testing"

	"github.com/syncthing/syncthing/lib/config"
)

func TestProxyHeaderAuthentication(t *testing.T) {
	p, err := newProxyAuthenticator(config.GUIProxyAuthConfiguration{
		Mode:           config.ProxyAuthModeHeader,
		TrustedProxies: "127.0.0.1/32",
		AllowedUsers:   "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		remote, user string
		wantOK       bool
		wantErr      bool
	}{
		{"127.0.0.1:1234", "alice", true, false},
		{"192.0.2.1:1234", "alice", false, true},
		{"127.0.0.1:1234", "bob", false, true},
		{"127.0.0.1:1234", "", false, false},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		r.Header.Set("Remote-User", tc.user)
		_, ok, err := p.authenticate(r)
		if ok != tc.wantOK || (err != nil) != tc.wantErr {
			t.Errorf("remote=%q user=%q: ok=%v err=%v", tc.remote, tc.user, ok, err)
		}
	}
}

func TestProxyHeaderRequiresTrustedAddress(t *testing.T) {
	_, err := newProxyAuthenticator(config.GUIProxyAuthConfiguration{Mode: config.ProxyAuthModeHeader})
	if err == nil {
		t.Fatal("header mode must require trustedProxies")
	}
}
