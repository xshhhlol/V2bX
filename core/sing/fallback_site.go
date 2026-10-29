package sing

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/port80"
	"github.com/InazumaV/V2bX/conf"
	"github.com/sagernet/sing-box/log"
)

//go:embed site
var defaultSite embed.FS

// fallbackSites runs the built-in fallback websites, shared by all nodes:
// per site root one loopback HTTP/1.1 server and one h2c server, plus the
// optional port 80 redirect.
type fallbackSites struct {
	access   sync.Mutex
	servers  []*http.Server
	addrs    map[string][2]string
	redirect bool
}

// applyFallbackSite points trojan and anytls TLS nodes, and VMess nodes
// without transport, with FallBackSite enabled at the built-in site. The
// returned options are a copy.
func (b *Sing) applyFallbackSite(info *panel.NodeInfo, config *conf.Options) (*conf.Options, error) {
	options := config.SingOptions
	if options == nil || options.FallBackSite == nil || !options.FallBackSite.Enabled {
		return config, nil
	}
	if !fallbackSiteApplies(info) {
		return config, nil
	}
	if fb := options.FallBackConfigs; fb != nil && (fb.FallBack.ServerPort != "" || len(fb.FallBackForALPN) > 0) {
		return config, nil
	}
	site := options.FallBackSite
	if info.Security != panel.Tls && site.RedirectHTTP {
		// Port 80 redirects to https, which a node without TLS cannot serve.
		withoutRedirect := *site
		withoutRedirect.RedirectHTTP = false
		site = &withoutRedirect
	}
	h1Addr, h2Addr, err := b.sites.serve(site)
	if err != nil {
		return nil, err
	}
	h1, h2 := fallbackOf(h1Addr), fallbackOf(h2Addr)
	newOptions := *options
	newOptions.FallBackConfigs = &conf.FallBackConfigForSing{
		FallBack:        h1,
		FallBackForALPN: map[string]conf.FallBack{"http/1.1": h1, "h2": h2},
	}
	if len(newOptions.ALPN) == 0 {
		newOptions.ALPN = []string{"h2", "http/1.1"}
	}
	newConfig := *config
	newConfig.SingOptions = &newOptions
	return &newConfig, nil
}

func fallbackSiteApplies(info *panel.NodeInfo) bool {
	switch info.Type {
	case "trojan", "anytls":
		return info.Security == panel.Tls
	case "vmess":
		return info.Security != panel.Reality && vmessWithoutTransport(info.VAllss)
	}
	return false
}

// vmessWithoutTransport mirrors getInboundOptions: tcp without an http
// header has no transport, so VMess itself sees every probe.
func vmessWithoutTransport(n *panel.VAllssNode) bool {
	if n == nil || n.Network != "tcp" {
		return false
	}
	if len(n.NetworkSettings) == 0 {
		return true
	}
	var network HttpNetworkConfig
	if err := json.Unmarshal(n.NetworkSettings, &network); err != nil {
		return false
	}
	return network.Header.Type != "http"
}

func fallbackOf(addr string) conf.FallBack {
	host, port, _ := net.SplitHostPort(addr)
	return conf.FallBack{Server: host, ServerPort: port}
}

// serve returns the HTTP/1.1 and h2c addresses of the site. They are separate
// listeners: a server accepting both must read 24 bytes to look for the
// HTTP/2 preface, and would hang on a shorter request instead of answering 400.
func (s *fallbackSites) serve(config *conf.FallBackSiteConfig) (string, string, error) {
	s.access.Lock()
	defer s.access.Unlock()
	if config.RedirectHTTP && !s.redirect {
		if err := port80.EnableRedirect(); err != nil {
			log.Warn("fallback site: port 80 redirect disabled: ", err)
		} else {
			s.redirect = true
		}
	}
	if addrs, ok := s.addrs[config.Root]; ok {
		return addrs[0], addrs[1], nil
	}
	handler := siteHandler(siteFS(config.Root))
	var addrs [2]string
	var servers []*http.Server
	for i := range addrs {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			for _, server := range servers {
				server.Close()
			}
			return "", "", err
		}
		server := &http.Server{
			Handler:           handler,
			Protocols:         new(http.Protocols),
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       2 * time.Minute,
		}
		if i == 0 {
			server.Protocols.SetHTTP1(true)
		} else {
			server.Protocols.SetUnencryptedHTTP2(true)
		}
		go server.Serve(listener)
		servers = append(servers, server)
		addrs[i] = listener.Addr().String()
	}
	if s.addrs == nil {
		s.addrs = make(map[string][2]string)
	}
	s.servers = append(s.servers, servers...)
	s.addrs[config.Root] = addrs
	return addrs[0], addrs[1], nil
}

func (s *fallbackSites) Close() {
	s.access.Lock()
	defer s.access.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, server := range s.servers {
		server.Shutdown(ctx)
	}
	if s.redirect {
		port80.DisableRedirect()
	}
	s.servers, s.addrs, s.redirect = nil, nil, false
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
		contentName := name
		if err == nil && stat.IsDir() {
			contentName = path.Join(name, "index.html")
			stat, err = fs.Stat(fsys, contentName)
		}
		if err != nil || strings.Contains("/"+name, "/.") && name != "." {
			http.NotFound(w, r)
			return
		}
		// Embedded files have no modification time, so FileServer cannot supply
		// Last-Modified. Give those files a content validator and let net/http
		// handle conditional and range requests. Disk files retain their normal
		// modification-time validation, including live edits to a custom root.
		if stat.Mode().IsRegular() && stat.ModTime().IsZero() {
			if file, openErr := fsys.Open(contentName); openErr == nil {
				hash := sha256.New()
				_, hashErr := io.Copy(hash, file)
				file.Close()
				if hashErr == nil {
					w.Header().Set("ETag", fmt.Sprintf(`"%x"`, hash.Sum(nil)))
				}
			}
		}
		fileServer.ServeHTTP(w, r)
	})
}
