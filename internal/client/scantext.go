package client

import (
	"bytes"
	"fmt"
)

// NormalizeScanText prepares scanner output read from a file or a pipe for
// upload. PowerShell's > writes UTF-16, which no scanner output parser reads,
// so UTF-16 text is refused with a message that names the fix. A UTF-8 byte
// order mark, which many Windows editors and tools add, is dropped: it is
// harmless text but makes the file invalid JSON. name labels the input in the
// error.
func NormalizeScanText(name string, data []byte) ([]byte, error) {
	if bytes.HasPrefix(data, []byte{0xFF, 0xFE}) || bytes.HasPrefix(data, []byte{0xFE, 0xFF}) {
		return nil, fmt.Errorf("%s is UTF-16 text, which Specht cannot read: save it as UTF-8 and upload it again", name)
	}
	return bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}), nil
}
