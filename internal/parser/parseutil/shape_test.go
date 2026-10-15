package parseutil

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadShape(t *testing.T) {
	t.Run("an object exposes its keys", func(t *testing.T) {
		s, ok := ReadShape([]byte(` {"a": 1, "b": "x", "c": [1, 2], "d": null} `))
		require.True(t, ok)
		assert.True(t, s.IsObject())
		assert.False(t, s.IsArray())
		assert.True(t, s.Has("a"))
		assert.True(t, s.Has("d"), "a key with a null value is present")
		assert.False(t, s.Has("z"))
		assert.Equal(t, "x", s.String("b"))
		assert.Empty(t, s.String("a"), "a number is not a string")
	})

	t.Run("an array exposes its elements, empty or not", func(t *testing.T) {
		s, ok := ReadShape([]byte(`[{"a":1},{"a":2}]`))
		require.True(t, ok)
		assert.True(t, s.IsArray())
		assert.Len(t, s.Array, 2)

		empty, ok := ReadShape([]byte(`[]`))
		require.True(t, ok)
		assert.True(t, empty.IsArray())
		assert.Empty(t, empty.Array)
	})

	t.Run("null is its own shape", func(t *testing.T) {
		s, ok := ReadShape([]byte(`null`))
		require.True(t, ok)
		assert.True(t, s.IsNull())
		assert.False(t, s.IsObject())
		assert.False(t, s.IsArray())
	})

	t.Run("scalars and broken input are not a shape", func(t *testing.T) {
		for _, in := range []string{``, `   `, `42`, `"text"`, `true`, `{"a":`, `[1,`, `not json`} {
			_, ok := ReadShape([]byte(in))
			assert.False(t, ok, in)
		}
	})
}

func TestShapeList(t *testing.T) {
	s, _ := ReadShape([]byte(`{"full":[1,2],"empty":[],"nothing":null,"obj":{},"num":3}`))

	items, ok := s.List("full")
	assert.True(t, ok)
	assert.Len(t, items, 2)

	items, ok = s.List("empty")
	assert.True(t, ok)
	assert.Empty(t, items)

	items, ok = s.List("nothing")
	assert.True(t, ok, "a null list is an empty list")
	assert.Empty(t, items)

	for _, key := range []string{"obj", "num", "absent"} {
		_, ok = s.List(key)
		assert.False(t, ok, key)
	}
}

func TestObjectHas(t *testing.T) {
	assert.True(t, ObjectHas(json.RawMessage(`{"a":1,"b":null}`), "a", "b"))
	assert.False(t, ObjectHas(json.RawMessage(`{"a":1}`), "a", "b"))
	assert.False(t, ObjectHas(json.RawMessage(`[1]`), "a"))
	assert.False(t, ObjectHas(json.RawMessage(`null`), "a"))
	assert.False(t, ObjectHas(nil, "a"))
}
