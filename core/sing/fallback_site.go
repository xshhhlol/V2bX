package sing

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	"github.com/sagernet/sing-box/log"
)

//go:embed site
var defaultSite embed.FS

// fallbackSites runs the built-in fallback websites, one loopback server per
// site root shared by all nodes, plus the optional port 80 redirect.
type fallbackSites struct {
	access   sync.Mutex
	servers  map[string]*http.Server
	addrs    map[string]string
	redirect *http.Server
}

// applyFallbackSite points trojan and anytls TLS nodes with FallBackSite
// enabled at the built-in site. The returned options are a copy.
func (b *Sing) applyFallbackSite(info *panel.NodeInfo, config *conf.Options) (*conf.Options, error) {
	options := config.SingOptions
	if options == nil || options.FallBackSite == nil || !options.FallBackSite.Enabled {
		return config, nil
	}
	if info.Type != "trojan" && info.Type != "anytls" || info.Security != panel.Tls {
		return config, nil
	}
	if fb := options.FallBackConfigs; fb != nil && (fb.FallBack.ServerPort != "" || len(fb.FallBackForALPN) > 0) {
		return config, nil
	}
	addr, err := b.sites.serve(options.FallBackSite)
	if err != nil {
		return nil, err
	}
	host, port, _ := net.SplitHostPort(addr)
	site := conf.FallBack{Server: host, ServerPort: port}
	newOptions := *options
	// One listener speaks both HTTP/1.1 and prior-knowledge HTTP/2.
	newOptions.FallBackConfigs = &conf.FallBackConfigForSing{
		FallBack:        site,
		FallBackForALPN: map[string]conf.FallBack{"http/1.1": site, "h2": site},
	}
	if len(newOptions.ALPN) == 0 {
		newOptions.ALPN = []string{"h2", "http/1.1"}
	}
	newConfig := *config
	newConfig.SingOptions = &newOptions
	return &newConfig, nil
}

func (s *fallbackSites) serve(config *conf.FallBackSiteConfig) (string, error) {
	s.access.Lock()
	defer s.access.Unlock()
	if config.RedirectHTTP && s.redirect == nil {
		s.redirect = startRedirect()
	}
	if addr, ok := s.addrs[config.Root]; ok {
		return addr, nil
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	server := &http.Server{
		Handler:           siteHandler(siteFS(config.Root)),
		Protocols:         new(http.Protocols),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	server.Protocols.SetHTTP1(true)
	server.Protocols.SetUnencryptedHTTP2(true)
	go server.Serve(listener)
	if s.servers == nil {
		s.servers = make(map[string]*http.Server)
		s.addrs = make(map[string]string)
	}
	addr := listener.Addr().String()
	s.servers[config.Root] = server
	s.addrs[config.Root] = addr
	return addr, nil
}

func (s *fallbackSites) Close() {
	s.access.Lock()
	defer s.access.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, server := range s.servers {
		server.Shutdown(ctx)
	}
	if s.redirect != nil {
		s.redirect.Shutdown(ctx)
	}
	s.servers, s.addrs, s.redirect = nil, nil, nil
}

func siteFS(root string) fs.FS {
	if root != "" {
		if stat, err := os.Stat(root); err == nil && stat.IsDir() {
			return os.DirFS(root)
		}
		log.Warn("fallback site root ", root, " is not a directory, using the built-in page")
	}
	sub, _ := fs.Sub(defaultSite, "site")
	return sub
}

// siteHandler serves static files like a plain file server: GET and HEAD only,
// index.html for directories and no directory listings.
func siteHandler(fsys fs.FS) http.Handler {
	fileServer := http.FileServerFS(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			name = "."
		}
		stat, err := fs.Stat(fsys, name)
		if err == nil && stat.IsDir() {
			_, err = fs.Stat(fsys, path.Join(name, "index.html"))
		}
		if err != nil || strings.Contains("/"+name, "/.") && name != "." {
			http.NotFound(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

func startRedirect() *http.Server {
	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		log.Warn("fallback site: port 80 redirect disabled: ", err)
		return nil
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			host = strings.Trim(host, "[]")
			if host == "" || strings.ContainsAny(host, "/\\@") {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			if strings.Contains(host, ":") {
				host = "[" + host + "]"
			}
			http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
		}),
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn("fallback site: port 80 redirect stopped: ", err)
		}
	}()
	return server
}
