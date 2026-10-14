package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Several client methods marshal their payload before handing it to the
// request builder. The builder must send those bytes as they are: encoding
// them again turned the body into a base64 string, which the server rejects.
func TestPreEncodedBodiesAreSentAsTheyAre(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got), "the body is a JSON object, not a JSON string")
		_, err := w.Write([]byte(`{"team_id":"t1","user_id":"u1","role":"member"}`))
		assert.NoError(t, err)
	}))
	defer srv.Close()

	_, err := New(srv.URL, WithToken("t")).AddTeamMember("t1", "u1", "member")

	require.NoError(t, err)
	assert.Equal(t, map[string]any{"user_id": "u1", "role": "member"}, got)
}

func TestRawMessageBodiesAreSentAsTheyAre(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_, err := w.Write([]byte(`{}`))
		assert.NoError(t, err)
	}))
	defer srv.Close()

	c := New(srv.URL, WithToken("t"))
	var out map[string]any
	require.NoError(t, c.do(t.Context(), "POST", "/x", json.RawMessage(`{"a":1}`), &out))

	assert.Equal(t, map[string]any{"a": float64(1)}, got)
}
