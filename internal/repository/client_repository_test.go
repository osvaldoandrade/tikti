package repository

import (
	"context"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func newClientRepoForTest(t *testing.T) (*redis.Client, ClientRepository) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, NewClientRepo(rdb)
}

func TestNewClientRepo(t *testing.T) {
	_, repo := newClientRepoForTest(t)
	if repo == nil {
		t.Fatalf("expected repo")
	}
}

func TestClientRepo_CreateGetList(t *testing.T) {
	_, repo := newClientRepoForTest(t)
	ctx := context.Background()
	r := repo.(*clientRepo)

	c := &domain.Client{Id: "c1", Type: domain.ClientTypeService}
	if err := r.Create(ctx, "t1", c); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	got, err := r.Get(ctx, "t1", "c1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got == nil || got.Id != "c1" {
		t.Fatalf("unexpected client: %+v", got)
	}

	list, err := r.List(ctx, "t1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(list) != 1 || list[0].Id != "c1" {
		t.Fatalf("unexpected list: %+v", list)
	}
}

func TestClientRepo_CreateInvalidArgument(t *testing.T) {
	_, repo := newClientRepoForTest(t)
	ctx := context.Background()
	r := repo.(*clientRepo)

	if err := r.Create(ctx, "", &domain.Client{Id: "c1"}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for empty tenant, got %v", err)
	}
	if err := r.Create(ctx, "t1", nil); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for nil client, got %v", err)
	}
	if err := r.Create(ctx, "t1", &domain.Client{}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for empty client id, got %v", err)
	}
}

func TestClientRepo_GetNotFoundAndInvalidJSON(t *testing.T) {
	rdb, repo := newClientRepoForTest(t)
	ctx := context.Background()
	r := repo.(*clientRepo)

	got, err := r.Get(ctx, "t1", "missing")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil client")
	}

	if err := rdb.HSet(ctx, clientsKey("t1"), "bad", "{").Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	if _, err := r.Get(ctx, "t1", "bad"); err == nil {
		t.Fatalf("expected unmarshal error")
	}
}

func TestClientRepo_ListInvalidJSON(t *testing.T) {
	rdb, repo := newClientRepoForTest(t)
	ctx := context.Background()
	r := repo.(*clientRepo)

	if err := rdb.HSet(ctx, clientsKey("t1"), "bad", "{").Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	if _, err := r.List(ctx, "t1"); err == nil {
		t.Fatalf("expected unmarshal error")
	}
}

func TestClientsKey(t *testing.T) {
	if got := clientsKey("x"); got != "clients:x" {
		t.Fatalf("unexpected key: %s", got)
	}
}
