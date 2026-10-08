package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/netutil"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { return len(p), nil }

func TestExchangeCode_RefusesAnOversizedTokenResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"`))
		_, _ = io.CopyN(w, zeroReader{}, maxTokenResponseBytes+1)
	}))
	defer srv.Close()

	_, err := mustOIDC(t, srv.URL).exchangeCode(context.Background(), "code", "")

	require.Error(t, err)
	assert.ErrorIs(t, err, netutil.ErrBodyTooLarge)
}

func TestExchangeCode_StillAcceptsANormalTokenResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","id_token":"it","token_type":"Bearer"}`))
	}))
	defer srv.Close()

	resp, err := mustOIDC(t, srv.URL).exchangeCode(context.Background(), "code", "")

	require.NoError(t, err)
	assert.Equal(t, "at", resp["access_token"])
}
