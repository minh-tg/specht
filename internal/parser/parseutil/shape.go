package parseutil

import (
	"bytes"
	"encoding/json"
)

// Shape is the top level of a JSON document: its keys when it is an object,
// its elements when it is an array. Parsers use it to grade a document without
// decoding it into their full model.
type Shape struct {
	Object map[string]json.RawMessage
	Array  []json.RawMessage
	null   bool
}

// ReadShape reads the top level of data. It reports false for anything that
// is not a JSON object, array or null, including input that is cut off.
func ReadShape(data []byte) (Shape, bool) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return Shape{}, false
	}
	switch trimmed[0] {
	case '{':
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return Shape{}, false
		}
		if obj == nil {
			obj = map[string]json.RawMessage{}
		}
		return Shape{Object: obj}, true
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return Shape{}, false
		}
		if arr == nil {
			arr = []json.RawMessage{}
		}
		return Shape{Array: arr}, true
	case 'n':
		if bytes.Equal(trimmed, []byte("null")) {
			return Shape{null: true}, true
		}
	}
	return Shape{}, false
}

// IsObject reports whether the document is a JSON object.
func (s Shape) IsObject() bool { return s.Object != nil }

// IsArray reports whether the document is a JSON array, possibly empty.
func (s Shape) IsArray() bool { return s.Array != nil }

// IsNull reports whether the document is the JSON value null.
func (s Shape) IsNull() bool { return s.null }

// Has reports whether the object has the key, even with a null value.
func (s Shape) Has(key string) bool {
	_, ok := s.Object[key]
	return ok
}

// String returns the value at key when it is a JSON string, else "".
func (s Shape) String(key string) string {
	raw, ok := s.Object[key]
	if !ok {
		return ""
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	return v
}

// List returns the elements at key. A null value is an empty list. It
// reports false when the key is absent or its value is not an array.
func (s Shape) List(key string) ([]json.RawMessage, bool) {
	raw, ok := s.Object[key]
	if !ok {
		return nil, false
	}
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return nil, true
	}
	var items []json.RawMessage
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return nil, false
	}
	return items, true
}

// ObjectHas reports whether raw is a JSON object that has every one of keys.
func ObjectHas(raw json.RawMessage, keys ...string) bool {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return false
	}
	for _, k := range keys {
		if _, ok := obj[k]; !ok {
			return false
		}
	}
	return true
}
