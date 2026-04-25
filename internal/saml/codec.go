package saml

import (
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

func init() {
	msgpack.RegisterExt(1, (*timeExt)(nil))
}

// timeExt encodes time.Time as RFC 3339 with nanosecond precision.
type timeExt struct {
	time.Time
}

func (t timeExt) MarshalMsgpack() ([]byte, error) {
	return []byte(t.Time.Format(time.RFC3339Nano)), nil
}

func (t *timeExt) UnmarshalMsgpack(b []byte) error {
	parsed, err := time.Parse(time.RFC3339Nano, string(b))
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
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
