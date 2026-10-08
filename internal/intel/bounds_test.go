package intel

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

func oversizedFeed(limit int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"`))
		_, _ = io.CopyN(w, zeroReader{}, limit+1)
	}))
}

func TestEPSSFetch_RefusesAnOversizedFeed(t *testing.T) {
	srv := oversizedFeed(maxEPSSResponseBytes)
	defer srv.Close()

	_, err := (&EPSSProvider{BaseURL: srv.URL}).Fetch(context.Background(), []string{"CVE-2024-0001"})

	require.Error(t, err)
	assert.ErrorIs(t, err, netutil.ErrBodyTooLarge)
}

func TestKEVFetch_RefusesAnOversizedCatalog(t *testing.T) {
	srv := oversizedFeed(maxKEVResponseBytes)
	defer srv.Close()

	_, err := (&KEVProvider{CatalogURL: srv.URL}).Fetch(context.Background(), []string{"CVE-2024-0001"})

	require.Error(t, err)
	assert.ErrorIs(t, err, netutil.ErrBodyTooLarge)
}
