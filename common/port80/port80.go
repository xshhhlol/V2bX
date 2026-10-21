// Package port80 shares port 80 between ACME HTTP-01 challenges and the
// https redirect of the fallback site, so certificates can be issued and
// renewed while the redirect keeps running.
package port80

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/http01"
	log "github.com/sirupsen/logrus"
)

// listenAddr is a variable for tests.
var listenAddr = ":80"

var (
	access   sync.Mutex
	tokens   = map[string]challenge{}
	redirect bool
	server   *http.Server
)

type challenge struct {
	domain  string
	keyAuth string
}

// EnableRedirect starts redirecting port 80 to https.
func EnableRedirect() error {
	access.Lock()
	defer access.Unlock()
	redirect = true
	return start()
}

// DisableRedirect stops the redirect; port 80 is released unless a
// challenge is still being served.
func DisableRedirect() {
	access.Lock()
	defer access.Unlock()
	redirect = false
	stopIfIdle()
}

// Provider is a lego HTTP-01 provider that serves challenges on the shared
// port 80 listener, starting it only while needed.
type Provider struct{}

func (Provider) Present(domain, token, keyAuth string) error {
	access.Lock()
	defer access.Unlock()
	tokens[token] = challenge{domain: domain, keyAuth: keyAuth}
	if err := start(); err != nil {
		delete(tokens, token)
		return err
	}
	return nil
}

func (Provider) CleanUp(_, token, _ string) error {
	access.Lock()
	defer access.Unlock()
	delete(tokens, token)
	stopIfIdle()
	return nil
}

func start() error {
	if server != nil {
		return nil
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	s := &http.Server{
		Handler:           http.HandlerFunc(serveHTTP),
		ReadHeaderTimeout: 30 * time.Second,
	}
	server = s
	go func() {
		if err := s.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn("port 80 server stopped: ", err)
		}
	}()
	return nil
}

func stopIfIdle() {
	if server == nil || redirect || len(tokens) > 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	server.Shutdown(ctx)
	server = nil
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if token, ok := strings.CutPrefix(r.URL.Path, http01.ChallengePath("")); ok {
		access.Lock()
		c, found := tokens[token]
		access.Unlock()
		// Like lego's own server, answer only GET for the challenged domain.
		if found && r.Method == http.MethodGet && strings.EqualFold(host, c.domain) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(c.keyAuth))
			return
		}
	}
	access.Lock()
	redirecting := redirect
	access.Unlock()
	if !redirecting {
		http.NotFound(w, r)
		return
	}
	if host == "" || strings.ContainsAny(host, "/\\@") {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
}
