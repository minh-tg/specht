package main

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRefreshWorkerUsesStableURLWithRevalidation(t *testing.T) {
	w := httptest.NewRecorder()
	setSPAHeaders(w, "session-refresh.js")
	assert.Equal(t, "no-cache", w.Header().Get("Cache-Control"))
	assert.Contains(t, w.Header().Get("Content-Type"), "javascript")
}
