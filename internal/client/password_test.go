package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChangePassword_SendsBothPasswordsAndReturnsTheNewSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/me/password", r.URL.Path)
		assert.Equal(t, "Bearer old-token", r.Header.Get("Authorization"))
		var got map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		assert.Equal(t, map[string]string{"current_password": "old-password", "new_password": "new-password"}, got)
		_, err := w.Write([]byte(`{"token":"fresh","refresh_token":"fresh-refresh","user_id":"u1","email":"a@b.co"}`))
		assert.NoError(t, err)
	}))
	defer srv.Close()

	resp, err := New(srv.URL, WithToken("old-token")).ChangePassword("old-password", "new-password")
	require.NoError(t, err)
	assert.Equal(t, "fresh", resp.Token)
	assert.Equal(t, "fresh-refresh", resp.RefreshToken)
}

func TestChangePassword_SurfacesTheServerMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte(`{"error":{"code":"wrong_password","message":"the current password is not correct"}}`))
		assert.NoError(t, err)
	}))
	defer srv.Close()

	_, err := New(srv.URL, WithToken("t")).ChangePassword("nope", "new-password")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "the current password is not correct")
}
