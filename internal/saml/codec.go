package saml

import (
	"reflect"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

func init() {
	msgpack.Register(
		time.Time{},
		func(enc *msgpack.Encoder, v reflect.Value) error {
			t := v.Interface().(time.Time)
			return enc.EncodeString(t.Format(time.RFC3339Nano))
		},
		func(dec *msgpack.Decoder, v reflect.Value) error {
			s, err := dec.DecodeString()
			if err != nil {
				return err
			}
			t, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				return err
			}
			v.Set(reflect.ValueOf(t))
			return nil
		},
	)
}

// encode serialises any value to msgpack bytes.
func encode[T any](v T) ([]byte, error) {
	return msgpack.Marshal(v)
}

// decode deserialises msgpack bytes into the given type.
func decode[T any](raw []byte) (T, error) {
	var v T
	err := msgpack.Unmarshal(raw, &v)
	return v, err
}
