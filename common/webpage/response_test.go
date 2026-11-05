package webpage

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

func TestCustomErrorsAndFileErrors(t *testing.T) {
	root := fstest.MapFS{"404.html": {Data: []byte("<html>Custom missing page</html>")}, "index.html": {Data: []byte("hello")}}
	for _, method := range []string{"GET", "HEAD"} {
		request := httptest.NewRequest(method, "http://example/missing", nil)
		response := httptest.NewRecorder()
		http.NotFound(Wrap(response, request, root), request)
		if response.Code != 404 || response.Header().Get("Content-Length") != strconv.Itoa(len(root["404.html"].Data)) || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("custom error: %d %v", response.Code, response.Header())
		}
		if method == "HEAD" && response.Body.Len() != 0 {
			t.Fatal("HEAD returned a body")
		}
		if method == "GET" && response.Body.String() != string(root["404.html"].Data) {
			t.Fatal(response.Body.String())
		}
	}
	request := httptest.NewRequest("GET", "http://example/404.html", nil)
	request.Header.Set("Range", "bytes=1000-2000")
	response := httptest.NewRecorder()
	http.FileServerFS(root).ServeHTTP(Wrap(response, request, root), request)
	if response.Code != 416 || response.Header().Get("Content-Range") == "" || !strings.Contains(response.Body.String(), "<html") {
		t.Fatalf("range error: %d %v %s", response.Code, response.Header(), response.Body.String())
	}
}
