package netutil

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadAllLimited(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		limit   int64
		want    string
		wantErr error
	}{
		{"well under the limit", "hello", 10, "hello", nil},
		{"exactly the limit", "0123456789", 10, "0123456789", nil},
		{"one byte over", "0123456789X", 10, "", ErrBodyTooLarge},
		{"empty", "", 10, "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadAllLimited(strings.NewReader(tc.body), tc.limit)

			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, got, "nothing partial is handed back for an oversized body")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(got))
		})
	}
}

func TestReadAllLimited_StopsReadingPastTheLimit(t *testing.T) {
	src := &countingReader{r: bytes.NewReader(make([]byte, 1<<20))}

	_, err := ReadAllLimited(src, 1024)

	assert.ErrorIs(t, err, ErrBodyTooLarge)
	assert.LessOrEqual(t, src.n, int64(1024+512), "an oversized body must not be pulled in whole")
}

func TestReadAllLimited_PropagatesReadErrors(t *testing.T) {
	boom := errors.New("connection reset")

	_, err := ReadAllLimited(io.MultiReader(strings.NewReader("ab"), errReader{boom}), 100)

	assert.ErrorIs(t, err, boom)
	assert.NotErrorIs(t, err, ErrBodyTooLarge)
}

func TestDecodeJSONLimited(t *testing.T) {
	var v struct {
		A int `json:"a"`
	}

	require.NoError(t, DecodeJSONLimited(strings.NewReader(`{"a":7}`), 64, &v))
	assert.Equal(t, 7, v.A)

	err := DecodeJSONLimited(strings.NewReader(`{"a":7,"pad":"`+strings.Repeat("x", 200)+`"}`), 64, &v)
	assert.ErrorIs(t, err, ErrBodyTooLarge, "size is reported as such, not as a JSON syntax error")

	assert.Error(t, DecodeJSONLimited(strings.NewReader(`{"a":`), 64, &v), "malformed JSON still fails")
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }
