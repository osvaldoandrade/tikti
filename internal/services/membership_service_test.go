package services

import (
	"context"
	"errors"
	"testing"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeMembershipRepo struct {
	createFn            func(ctx context.Context, membership *domain.Membership) error
	getFn               func(ctx context.Context, tenantID string, userID string) (*domain.Membership, error)
	listTenantIDsByUser func(ctx context.Context, userID string) ([]string, error)
	deleteFn            func(ctx context.Context, tenantID string, userID string) error
}

func (f *fakeMembershipRepo) Create(ctx context.Context, membership *domain.Membership) error {
	if f.createFn != nil {
		return f.createFn(ctx, membership)
	}
	return nil
}
func (f *fakeMembershipRepo) Get(ctx context.Context, tenantID string, userID string) (*domain.Membership, error) {
	if f.getFn != nil {
		return f.getFn(ctx, tenantID, userID)
	}
	return nil, nil
}
func (f *fakeMembershipRepo) ListTenantIDsByUser(ctx context.Context, userID string) ([]string, error) {
	if f.listTenantIDsByUser != nil {
		return f.listTenantIDsByUser(ctx, userID)
	}
	return nil, nil
}
func (f *fakeMembershipRepo) Delete(ctx context.Context, tenantID string, userID string) error {
	if f.deleteFn != nil {
		return f.deleteFn(ctx, tenantID, userID)
	}
	return nil
}

type fakeMembershipUserRepo struct {
	findByEmailFn func(ctx context.Context, email string) (*domain.User, error)
	updateUserFn  func(ctx context.Context, user *domain.User) error
}

func (f *fakeMembershipUserRepo) CreateUser(ctx context.Context, user *domain.User) error {
	return nil
}
func (f *fakeMembershipUserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	if f.findByEmailFn != nil {
		return f.findByEmailFn(ctx, email)
	}
	return nil, nil
}
func (f *fakeMembershipUserRepo) UpdateUser(ctx context.Context, user *domain.User) error {
	if f.updateUserFn != nil {
		return f.updateUserFn(ctx, user)
	}
	return nil
}
func (f *fakeMembershipUserRepo) DeleteByEmail(ctx context.Context, email string) error {
	return nil
}
func (f *fakeMembershipUserRepo) SetStatus(ctx context.Context, email string, status domain.UserStatus) (*domain.User, error) {
	return nil, nil
}
func (f *fakeMembershipUserRepo) IncrementTokenVersion(ctx context.Context, email string) (int, *domain.User, error) {
	return 0, nil, nil
}
func (f *fakeMembershipUserRepo) SaveOobCode(ctx context.Context, code, email, reqType string) error {
	return nil
}
func (f *fakeMembershipUserRepo) ConsumeOobCode(ctx context.Context, code string, expectedReqType string) (string, error) {
	return "", nil
}
func (f *fakeMembershipUserRepo) GetAllUsers(ctx context.Context) ([]*domain.User, error) {
	return nil, nil
}

func TestNewMembershipService(t *testing.T) {
	svc := NewMembershipService(&fakeMembershipUserRepo{}, &fakeMembershipRepo{})
	if svc == nil {
		t.Fatalf("expected service")
	}
}

func TestMembershipService_Create(t *testing.T) {
	svc := NewMembershipService(&fakeMembershipUserRepo{}, &fakeMembershipRepo{})
	if _, err := svc.Create(context.Background(), "", domain.MembershipCreateReq{Email: "a@a.com"}); err != domain.ErrInvalidTenant {
		t.Fatalf("expected ErrInvalidTenant, got %v", err)
	}
	if _, err := svc.Create(context.Background(), "t1", domain.MembershipCreateReq{Email: ""}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}

	repoErr := errors.New("find-fail")
	svc = NewMembershipService(&fakeMembershipUserRepo{
		findByEmailFn: func(ctx context.Context, email string) (*domain.User, error) { return nil, repoErr },
	}, &fakeMembershipRepo{})
	if _, err := svc.Create(context.Background(), "t1", domain.MembershipCreateReq{Email: "a@a.com"}); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}

	svc = NewMembershipService(&fakeMembershipUserRepo{
		findByEmailFn: func(ctx context.Context, email string) (*domain.User, error) { return nil, nil },
	}, &fakeMembershipRepo{})
	if _, err := svc.Create(context.Background(), "t1", domain.MembershipCreateReq{Email: "a@a.com"}); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	repoErr = errors.New("create-fail")
	user := &domain.User{Id: "u1", Email: "u1@x.com"}
	svc = NewMembershipService(&fakeMembershipUserRepo{
		findByEmailFn: func(ctx context.Context, email string) (*domain.User, error) { return user, nil },
	}, &fakeMembershipRepo{
		createFn: func(ctx context.Context, membership *domain.Membership) error { return repoErr },
	})
	if _, err := svc.Create(context.Background(), "t1", domain.MembershipCreateReq{Email: user.Email}); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}

	updated := false
	user = &domain.User{Id: "u1", Email: "u1@x.com"}
	svc = NewMembershipService(&fakeMembershipUserRepo{
		findByEmailFn: func(ctx context.Context, email string) (*domain.User, error) { return user, nil },
		updateUserFn: func(ctx context.Context, u *domain.User) error {
			updated = true
			return nil
		},
	}, &fakeMembershipRepo{
		createFn: func(ctx context.Context, membership *domain.Membership) error {
			if membership.Id == "" {
				t.Fatalf("expected membership id")
			}
			return nil
		},
	})
	resp, err := svc.Create(context.Background(), "t1", domain.MembershipCreateReq{Email: user.Email, Roles: []string{"R1"}})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !updated {
		t.Fatalf("expected user update when CompanyId nil")
	}
	if resp.UserId != "u1" || resp.TenantId != "t1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestMembershipService_Remove(t *testing.T) {
	svc := NewMembershipService(&fakeMembershipUserRepo{}, &fakeMembershipRepo{})
	if _, err := svc.Remove(context.Background(), "", domain.MembershipRemoveReq{Email: "x"}); err != domain.ErrInvalidTenant {
		t.Fatalf("expected ErrInvalidTenant, got %v", err)
	}
	if _, err := svc.Remove(context.Background(), "t1", domain.MembershipRemoveReq{Email: ""}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}

	repoErr := errors.New("find-fail")
	svc = NewMembershipService(&fakeMembershipUserRepo{
		findByEmailFn: func(ctx context.Context, email string) (*domain.User, error) { return nil, repoErr },
	}, &fakeMembershipRepo{})
	if _, err := svc.Remove(context.Background(), "t1", domain.MembershipRemoveReq{Email: "u@x.com"}); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}

	svc = NewMembershipService(&fakeMembershipUserRepo{
		findByEmailFn: func(ctx context.Context, email string) (*domain.User, error) { return nil, nil },
	}, &fakeMembershipRepo{})
	if _, err := svc.Remove(context.Background(), "t1", domain.MembershipRemoveReq{Email: "u@x.com"}); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	repoErr = errors.New("delete-fail")
	svc = NewMembershipService(&fakeMembershipUserRepo{
		findByEmailFn: func(ctx context.Context, email string) (*domain.User, error) {
			return &domain.User{Id: "u1", Email: email}, nil
		},
	}, &fakeMembershipRepo{
		deleteFn: func(ctx context.Context, tenantID string, userID string) error { return repoErr },
	})
	if _, err := svc.Remove(context.Background(), "t1", domain.MembershipRemoveReq{Email: "u@x.com"}); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}

	svc = NewMembershipService(&fakeMembershipUserRepo{
		findByEmailFn: func(ctx context.Context, email string) (*domain.User, error) {
			return &domain.User{Id: "u1", Email: email}, nil
		},
	}, &fakeMembershipRepo{})
	resp, err := svc.Remove(context.Background(), "t1", domain.MembershipRemoveReq{Email: "u@x.com"})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.UserId != "u1" || resp.TenantId != "t1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestMembershipService_ListTenantIDsByUser(t *testing.T) {
	repoErr := errors.New("repo-fail")
	svc := NewMembershipService(&fakeMembershipUserRepo{}, &fakeMembershipRepo{
		listTenantIDsByUser: func(ctx context.Context, userID string) ([]string, error) {
			return nil, repoErr
		},
	})
	if _, err := svc.ListTenantIDsByUser(context.Background(), "u1"); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}
}
