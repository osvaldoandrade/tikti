package managedlogs

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

var errJSON = errors.New("invalid workload identity JSON")

// Decode accepts exactly the canonical typed schema, without duplicate keys,
// case aliases, extra values, unbounded nesting or ambiguous response objects.
func Decode(raw []byte, destination any) error {
	t := reflect.TypeOf(destination)
	if len(raw) > 96<<10 || t == nil || t.Kind() != reflect.Pointer || reflect.ValueOf(destination).IsNil() {
		return errJSON
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if shape(d, t.Elem(), 0) != nil {
		return errJSON
	}
	if _, err := d.Token(); err != io.EOF {
		return errJSON
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(destination) != nil {
		return errJSON
	}
	return nil
}

func shape(d *json.Decoder, t reflect.Type, depth int) error {
	if depth > 8 {
		return errJSON
	}
	token, err := d.Token()
	if err != nil {
		return errJSON
	}
	if t.Kind() == reflect.Struct {
		if token != json.Delim('{') {
			return errJSON
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			fields[strings.Split(field.Tag.Get("json"), ",")[0]] = field.Type
		}
		seen := map[string]bool{}
		for d.More() {
			keyToken, err := d.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || seen[key] || fields[key] == nil {
				return errJSON
			}
			seen[key] = true
			if shape(d, fields[key], depth+1) != nil {
				return errJSON
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errJSON
		}
		return nil
	}
	if t.Kind() == reflect.Slice {
		if token != json.Delim('[') {
			return errJSON
		}
		count := 0
		for d.More() {
			count++
			if count > 256 || shape(d, t.Elem(), depth+1) != nil {
				return errJSON
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errJSON
		}
		return nil
	}
	if _, complex := token.(json.Delim); complex {
		return errJSON
	}
	return nil
}
