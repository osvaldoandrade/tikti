package saml

import (
	"context"
	"time"
)

// Compile-time interface compliance check.
var _ Store = (*stubStore)(nil)

// stubStore is an unimplemented stub used only for the compile-time assertion above.
type stubStore struct{}

func (s *stubStore) PutRequest(_ context.Context, _ RequestRecord) error {
	return nil
}

func (s *stubStore) ConsumeRequest(_ context.Context, _ string) (RequestRecord, bool, error) {
	return RequestRecord{}, false, nil
}

func (s *stubStore) PutIdP(_ context.Context, _ IdPRecord) error {
	return nil
}

func (s *stubStore) GetIdP(_ context.Context, _ string) (IdPRecord, error) {
	return IdPRecord{}, nil
}

func (s *stubStore) ListIdPs(_ context.Context) ([]IdPRecord, error) {
	return nil, nil
}

func (s *stubStore) DeleteIdP(_ context.Context, _ string) error {
	return nil
}

func (s *stubStore) PutIndex(_ context.Context, _ string, _ IndexRecord) error {
	return nil
}

func (s *stubStore) GetIndex(_ context.Context, _ string) (IndexRecord, error) {
	return IndexRecord{}, nil
}

func (s *stubStore) DeleteIndex(_ context.Context, _ string) error {
	return nil
}

func (s *stubStore) MarkSeen(_ context.Context, _ string, _ time.Duration) (bool, error) {
	return false, nil
}

func (s *stubStore) PutDomain(_ context.Context, _, _ string) error {
	return nil
}

func (s *stubStore) GetDomain(_ context.Context, _ string) (string, error) {
	return "", nil
}

func (s *stubStore) DeleteDomain(_ context.Context, _ string) error {
	return nil
}
