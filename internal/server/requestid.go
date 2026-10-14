package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/minh-tg/specht/internal/reqctx"
)

// requestIDHeader names the header that carries the id in both directions.
const requestIDHeader = "X-Request-Id"

// A caller may supply its own id so a trace can span services, but only a
// short, plain one: anything else could forge or split a log line.
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// RequestIDMiddleware gives every request an id, returns it in the
// X-Request-Id header, and puts it and the start time in the request context
// for the access log and the audit log.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if !requestIDPattern.MatchString(id) {
			id = newRequestID()
		}
		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(reqctx.With(r.Context(), id, time.Now())))
	})
}

// newRequestID returns 128 random bits as 32 hex characters.
func newRequestID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		// The system random source failing is not worth failing a request;
		// a time-based id still tells two requests apart in practice.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(raw)
}
