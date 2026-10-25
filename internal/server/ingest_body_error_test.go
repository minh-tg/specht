package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/usecase"
)

// failingBody returns its prefix and then a read error that none of the known
// cases describe, like a broken chunked encoding.
type failingBody struct {
	r   io.Reader
	err error
}

func (b *failingBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if errors.Is(err, io.EOF) {
		return n, b.err
	}
	return n, err
}

// Every way the ingest body can fail to read must produce an error answer.
// Two used to fall through respondIngestBodyError without writing, and
// net/http then sent an empty 200 that a CI client could take for success.
func TestIngestReport_UnreadableBodyIsNeverASilent200(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   io.Reader
		status int
	}{
		{"read error in the head", &failingBody{strings.NewReader(`{"project":"my-a`), errors.New("invalid byte in chunk length")}, http.StatusBadRequest},
		{"read error after the head", &failingBody{strings.NewReader(`{"project":"my-app","raw_data":{"a"`), errors.New("connection reset by peer")}, http.StatusBadRequest},
		{"body ends after a key", strings.NewReader(`{"scanner"`), http.StatusBadRequest},
		{"read deadline as a context error", &failingBody{strings.NewReader(`{"project":"my-app",`), context.DeadlineExceeded}, http.StatusRequestTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockUsecases{
				ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
					t.Fatal("an unreadable body must not reach the use case")
					return nil, nil
				},
			}
			req := httptest.NewRequest("POST", "/api/v1/reports", tc.body)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+testToken(t))
			w := httptest.NewRecorder()

			NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth}).ServeHTTP(w, req)

			assert.Equal(t, tc.status, w.Code, "body: %s", w.Body.String())
			assert.NotEmpty(t, w.Body.String())
		})
	}
}
