package port80

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestChallengeAndRedirect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr = listener.Addr().String()
	listener.Close()
	client := &http.Client{
		Timeout:       3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	get := func(host, path string) (int, string, string) {
		request, _ := http.NewRequest(http.MethodGet, "http://"+listenAddr+path, nil)
		request.Host = host
		response, err := client.Do(request)
		if err != nil {
			return 0, "", ""
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body), response.Header.Get("Location")
	}
	var provider Provider

	// Without the redirect the listener only lives while a challenge is pending.
	if err = provider.Present("node.example.com", "tok1", "tok1.auth"); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := get("node.example.com", "/.well-known/acme-challenge/tok1"); code != 200 || body != "tok1.auth" {
		t.Fatalf("challenge: %d %q", code, body)
	}
	if code, _, _ := get("other.example.com", "/.well-known/acme-challenge/tok1"); code != 404 {
		t.Fatalf("challenge for another host: %d", code)
	}
	provider.CleanUp("node.example.com", "tok1", "tok1.auth")
	if code, _, _ := get("node.example.com", "/"); code != 0 {
		t.Fatalf("port still open after cleanup: %d", code)
	}

	// With the redirect, challenges are served on the same listener and it
	// keeps running after cleanup.
	if err = EnableRedirect(); err != nil {
		t.Fatal(err)
	}
	if code, _, location := get("node.example.com", "/a?b=1"); code != 301 || location != "https://node.example.com/a?b=1" {
		t.Fatalf("redirect: %d %q", code, location)
	}
	if err = provider.Present("node.example.com", "tok2", "tok2.auth"); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := get("node.example.com:80", "/.well-known/acme-challenge/tok2"); code != 200 || body != "tok2.auth" {
		t.Fatalf("challenge during redirect: %d %q", code, body)
	}
	provider.CleanUp("node.example.com", "tok2", "tok2.auth")
	if code, _, _ := get("node.example.com", "/.well-known/acme-challenge/tok2"); code != 301 {
		t.Fatalf("stale challenge: %d", code)
	}
	DisableRedirect()
	if code, _, _ := get("node.example.com", "/"); code != 0 {
		t.Fatalf("port still open after disabling redirect: %d", code)
	}
}
