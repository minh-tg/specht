package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeScanText(t *testing.T) {
	got, err := NormalizeScanText("scan.json", []byte("\xEF\xBB\xBF{}"))
	require.NoError(t, err)
	assert.Equal(t, "{}", string(got), "a UTF-8 byte order mark is dropped")

	got, err = NormalizeScanText("scan.json", []byte("{}"))
	require.NoError(t, err)
	assert.Equal(t, "{}", string(got))

	for _, bom := range []string{"\xFF\xFE", "\xFE\xFF"} {
		_, err = NormalizeScanText("scan.json", []byte(bom+"{}"))
		assert.ErrorContains(t, err, "scan.json is UTF-16 text")
	}
}
