package domain

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeExaminedKeys(t *testing.T) {
	got := NormalizeExaminedKeys([]string{"rule:sast:b", "", "rule:sast:a", "rule:sast:b", strings.Repeat("x", 700)})
	assert.Equal(t, []string{"rule:sast:a", "rule:sast:b"}, got, "sorted, de-duplicated, empty and oversized keys dropped")
}

func TestNormalizeExaminedKeysOverTheLimitProvesNothing(t *testing.T) {
	keys := make([]string, 0, MaxExaminedKeys+1)
	for i := 0; i <= MaxExaminedKeys; i++ {
		keys = append(keys, ExaminedRunFile(0, strconv.Itoa(i)))
	}
	assert.Nil(t, NormalizeExaminedKeys(keys))
}
