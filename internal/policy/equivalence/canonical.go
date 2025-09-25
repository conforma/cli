package equivalence

import (
	"bytes"
	"encoding/json"
	"sort"
)

// marshalCanonical creates deterministic JSON by sorting map keys at every level
func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encodeCanonical recursively encodes JSON with sorted keys for deterministic output
func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case map[string]any:
		// Sort keys to ensure deterministic output
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			// Encode key (always a string, so use standard JSON encoding)
			keyBytes, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(keyBytes)
			buf.WriteByte(':')
			// Recursively encode value
			if err := encodeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		// For scalars (numbers, strings, bool, null), use standard JSON encoding
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}
