// Package webpage provides the public pages shared by the built-in website
// and the ACME/HTTPS redirect listener. It replaces application-level default
// error text, not the HTTP parser, HTTP/2 implementation or TLS stack.
package webpage

import (
	"html"
	"io"
	"io/fs"
	"net/http"
	"strconv"
)

const maxErrorPageSize = 64 << 10

// Error serves <status>.html from the website root when present, otherwise a
// small HTML page. Never reflect request paths, hosts or internal errors.
func Error(w http.ResponseWriter, r *http.Request, status int, root fs.FS) {
	body := page(status)
	if root != nil {
		if f, err := root.Open(strconv.Itoa(status) + ".html"); err == nil {
			defer f.Close()
			if info, err := f.Stat(); err == nil && info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= maxErrorPageSize {
				if custom, err := io.ReadAll(io.LimitReader(f, maxErrorPageSize+1)); err == nil && len(custom) > 0 && len(custom) <= maxErrorPageSize {
					body = string(custom)
				}
			}
		}
	}
	write(w, r, status, body)
}

// Redirect retains the caller's destination and status without net/http's
// default link-only response body.
func Redirect(w http.ResponseWriter, r *http.Request, location string, status int) {
	w.Header().Set("Location", location)
	write(w, r, status, page(status))
}

func page(status int) string {
	title := html.EscapeString(strconv.Itoa(status) + " " + http.StatusText(status))
	return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">" +
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>" + title +
		"</title></head><body><main><h1>" + title +
		"</h1><p>Please check the address or return to the home page.</p>" +
		"<p><a href=\"/\">Home</a></p></main></body></html>\n"
}

func write(w http.ResponseWriter, r *http.Request, status int, body string) {
	h := w.Header()
	// A file server may have set these before discovering an invalid range or
	// another error. Keep protocol headers such as Content-Range and Allow.
	for _, key := range []string{"ETag", "Last-Modified", "Accept-Ranges", "Content-Encoding"} {
		h.Del(key)
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		io.WriteString(w, body)
	}
}

// Wrap also handles errors and redirects emitted inside http.FileServer,
// including invalid ranges. Successful file bodies stream without buffering,
// preserving normal HEAD, range and conditional-request behavior.
func Wrap(w http.ResponseWriter, r *http.Request, root fs.FS) http.ResponseWriter {
	return &responseWriter{ResponseWriter: w, request: r, root: root}
}

type responseWriter struct {
	http.ResponseWriter
	request   *http.Request
	root      fs.FS
	committed bool
	replaced  bool
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseWriter) WriteHeader(status int) {
	if w.committed {
		return
	}
	if status < 200 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.committed = true
	if status >= 400 && status <= 599 {
		w.replaced = true
		Error(w.ResponseWriter, w.request, status, w.root)
		return
	}
	switch status {
	case 301, 302, 303, 307, 308:
		w.replaced = true
		Redirect(w.ResponseWriter, w.request, w.Header().Get("Location"), status)
		return
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	if w.replaced {
		return len(p), nil
	}
	return w.ResponseWriter.Write(p)
}

func (w *responseWriter) ReadFrom(r io.Reader) (int64, error) {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	if w.replaced {
		return io.Copy(io.Discard, r)
	}
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{w.ResponseWriter}, r)
}
