package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// errProjectNotInHead means the body did not name its project within the part
// of it that is read before the caller is authorized.
var errProjectNotInHead = errors.New("project not found in the head of the request body")

// errNotAnObject means the body is valid so far but is not a JSON object.
var errNotAnObject = errors.New("request body is not a JSON object")

// scanIngestProject finds the value of the top-level "project" key of a JSON
// object body by reading at most limit bytes of src. It returns the project
// and a reader that yields the whole body again: what was read, then the rest
// of src. Nothing past the project is parsed, so a caller who is refused never
// costs the decode of the report.
//
// Keys match the way encoding/json matches them for the struct that is decoded
// later (case-insensitively), and the first match wins. A body that repeats the
// key with another value is caught by the caller, which compares the decoded
// request's project with this one.
//
// A body that ends before naming a project returns "" and a nil error, so the
// caller can answer the way it does for any request without one. A body that
// does not name it within limit bytes returns errProjectNotInHead.
func scanIngestProject(src io.Reader, limit int) (project string, body io.Reader, err error) {
	var read bytes.Buffer
	lr := &io.LimitedReader{R: src, N: int64(limit)}
	dec := json.NewDecoder(io.TeeReader(lr, &read))
	project, err = findProject(dec)
	body = io.MultiReader(bytes.NewReader(read.Bytes()), src)
	if err != nil && lr.N == 0 && !isSyntaxError(err) {
		// The limit cut the body, not the caller: the key may still come.
		return "", body, errProjectNotInHead
	}
	return project, body, err
}

func isSyntaxError(err error) bool {
	var syntax *json.SyntaxError
	var typed *json.UnmarshalTypeError
	return errors.As(err, &syntax) || errors.As(err, &typed) || errors.Is(err, errNotAnObject)
}

func findProject(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if errors.Is(err, io.EOF) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return "", errNotAnObject
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", err
		}
		key, _ := keyTok.(string)
		if strings.EqualFold(key, "project") {
			var project string
			if err := dec.Decode(&project); err != nil {
				return "", err
			}
			return project, nil
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return "", err
		}
	}
	return "", nil
}
