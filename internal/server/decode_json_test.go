package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func decodeForTest(body string, max int64) (ok bool, got map[string]string, w *httptest.ResponseRecorder) {
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	got = map[string]string{}
	ok = decodeJSONBody(w, r, &got, max, "invalid_json", "invalid request body")
	return ok, got, w
}

func TestDecodeJSONBody_AcceptsOneValueWithSurroundingWhitespace(t *testing.T) {
	for _, body := range []string{`{"a":"b"}`, " \n{\"a\":\"b\"}\n\t ", `{"a":"b"}` + "\r\n"} {
		ok, got, w := decodeForTest(body, 1<<10)
		assert.True(t, ok, "%q", body)
		assert.Equal(t, "b", got["a"])
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func TestDecodeJSONBody_EmptyBodyKeepsTheZeroValue(t *testing.T) {
	ok, got, _ := decodeForTest("", 1<<10)
	assert.True(t, ok)
	assert.Empty(t, got)
}

func TestDecodeJSONBody_RejectsDataAfterTheValue(t *testing.T) {
	for _, body := range []string{
		`{"a":"b"} GARBAGE`,
		`{"a":"b"}{"a":"c"}`,
		`{"a":"b"} {"a":"c"}`,
		`{"a":"b"}]`,
		`{"a":"b"},`,
		`{"a":"b"} 1`,
	} {
		ok, _, w := decodeForTest(body, 1<<10)
		assert.False(t, ok, "%q", body)
		assert.Equal(t, http.StatusBadRequest, w.Code, "%q", body)
		assert.Contains(t, w.Body.String(), "invalid_json", "%q", body)
	}
}

func TestDecodeJSONBody_TrailingDataPastTheCapIsTooLarge(t *testing.T) {
	body := `{"a":"b"}` + strings.Repeat(" ", 64) + "x"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.ContentLength = -1 // chunked: only the mid-read cap applies
	var got map[string]string
	ok := decodeJSONBody(w, r, &got, 16, "invalid_json", "invalid request body")
	assert.False(t, ok)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}
