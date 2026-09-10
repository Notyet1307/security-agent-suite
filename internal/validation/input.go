package validation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

// StrictDecode rejects ambiguous JSON before typed decoding. Manual input never
// accepts null, replacement of malformed Unicode, duplicate keys or trailing data.
func StrictDecode(raw []byte, target any) error {
	invalid := func() error { return fmt.Errorf("%w: invalid strict JSON", domain.ErrInvalidRequest) }
	if !utf8.Valid(raw) || !validEscapes(raw) {
		return invalid()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 10000 {
			return invalid()
		}
		token, err := d.Token()
		if err != nil || token == nil {
			return invalid()
		}
		switch token {
		case json.Delim('{'):
			keys := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return invalid()
				}
				key, ok := k.(string)
				if !ok || keys[key] {
					return invalid()
				}
				keys[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return invalid()
			}
		case json.Delim('['):
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return invalid()
			}
		}
		return nil
	}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return invalid()
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return invalid()
	}
	var value any
	generic := json.NewDecoder(bytes.NewReader(raw))
	generic.UseNumber()
	if generic.Decode(&value) != nil || !exactFields(value, reflect.TypeOf(target).Elem()) {
		return invalid()
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return invalid()
	}
	return nil
}

// encoding/json replaces unpaired UTF-16 escapes. Check the original string
// tokens so a literal replacement character stays valid, but malformed escapes do not.
func validEscapes(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !inString
}

var alertID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func ValidateInput(raw []byte) error {
	var alert struct {
		Schema       string `json:"schema"`
		Synthetic    bool   `json:"synthetic"`
		AlertID      string `json:"alert_id"`
		Observations []struct {
			Source string `json:"source"`
			Text   string `json:"text"`
		} `json:"observations"`
	}
	if err := StrictDecode(raw, &alert); err != nil {
		return err
	}
	if alert.Schema != domain.InputSchema || !alert.Synthetic || len(alert.AlertID) > 128 || !alertID.MatchString(alert.AlertID) || alert.Observations == nil || len(alert.Observations) > 64 {
		return domain.ErrInvalidRequest
	}
	for _, o := range alert.Observations {
		if n := utf8.RuneCountInString(o.Source); n < 1 || n > 128 {
			return domain.ErrInvalidRequest
		}
		if n := utf8.RuneCountInString(o.Text); n < 1 || n > 16384 {
			return domain.ErrInvalidRequest
		}
	}
	return nil
}

func exactFields(value any, t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()) {
		return true
	}
	switch t.Kind() {
	case reflect.Struct:
		obj, ok := value.(map[string]any)
		if !ok {
			return false
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			fields[name] = f.Type
		}
		for k, v := range obj {
			ft, ok := fields[k]
			if !ok || !exactFields(v, ft) {
				return false
			}
		}
	case reflect.Slice:
		if arr, ok := value.([]any); ok {
			for _, v := range arr {
				if !exactFields(v, t.Elem()) {
					return false
				}
			}
		}
	case reflect.Map:
		if obj, ok := value.(map[string]any); ok {
			for _, v := range obj {
				if !exactFields(v, t.Elem()) {
					return false
				}
			}
		}
	}
	return true
}
