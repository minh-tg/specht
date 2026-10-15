package scanner_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/scanner"
)

func TestFingerprintKeyTravelsInTheContext(t *testing.T) {
	_, ok := scanner.FingerprintKey(context.Background())
	assert.False(t, ok, "a context without a key has none")

	key := []byte("0123456789abcdef0123456789abcdef")
	got, ok := scanner.FingerprintKey(scanner.WithFingerprintKey(context.Background(), key))
	require.True(t, ok)
	assert.Equal(t, key, got)
}

func TestAnEmptyKeyIsNoKey(t *testing.T) {
	_, ok := scanner.FingerprintKey(scanner.WithFingerprintKey(context.Background(), nil))
	assert.False(t, ok, "an empty key must never count as one, or every secret would hash alike")
}

func TestTheKeyIsCopiedSoACallerCannotChangeIt(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	ctx := scanner.WithFingerprintKey(context.Background(), key)
	key[0] = 'X'
	got, _ := scanner.FingerprintKey(ctx)
	assert.Equal(t, byte('0'), got[0])

	got[1] = 'Y'
	again, _ := scanner.FingerprintKey(ctx)
	assert.Equal(t, byte('1'), again[1], "reading the key hands out a copy too")
}

type keyedFake struct{ testScanner }

func (keyedFake) UsesFingerprintKey() bool { return true }

func TestUsesFingerprintKey(t *testing.T) {
	assert.False(t, scanner.UsesFingerprintKey(&testScanner{name: "plain", kind: "sca", version: "1"}))
	assert.True(t, scanner.UsesFingerprintKey(&keyedFake{testScanner{name: "keyed", kind: "secret", version: "1"}}))
	assert.False(t, scanner.UsesFingerprintKey(nil))
}

func TestFingerprintKeyRequiredIsTyped(t *testing.T) {
	err := scanner.KeyRequired("gitleaks")
	require.ErrorIs(t, err, scanner.ErrFingerprintKeyRequired)
	assert.Contains(t, err.Error(), "gitleaks")
}
