package nativeauth

import (
	"net/http"
	"strings"
)

// Mount isolates native redirects and credentials from generic router redirect
// correction, CORS and logging. Unknown aliases fail without a Location header.
func Mount(native, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == strings.TrimSuffix(PublicPrefix, "/") || strings.HasPrefix(path, PublicPrefix) || path == "/v1/native" || strings.HasPrefix(path, "/v1/native/") {
			if native == nil {
				http.NotFound(w, r)
				return
			}
			native.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
