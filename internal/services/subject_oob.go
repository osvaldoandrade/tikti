package services

import (
	"context"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func (s *userService) saveAccountOOB(ctx context.Context, code string, user *domain.User, request string) error {
	if bound, ok := s.repo.(repository.SubjectBoundOOBRepository); ok {
		return bound.SaveSubjectOobCode(ctx, code, repository.OOBSubject{UserID: user.Id, Email: user.Email, TokenVersion: user.TokenVersion}, request)
	}
	// Compatibility for repository adapters predating subject-bound credentials.
	// The production Redis repository always implements the stronger contract.
	return s.repo.SaveOobCode(ctx, code, user.Email, request)
}

func (s *userService) consumeAccountOOB(ctx context.Context, code, request string) (*domain.User, error) {
	if bound, ok := s.repo.(repository.SubjectBoundOOBRepository); ok {
		proof, err := bound.ConsumeSubjectOobCode(ctx, code, request)
		if err != nil {
			return nil, err
		}
		subjects, ok := s.repo.(repository.UserIDRepository)
		if !ok {
			return nil, domain.ErrInvalidOob
		}
		user, err := subjects.FindByID(ctx, proof.UserID)
		if err != nil {
			return nil, err
		}
		if user == nil || user.Id != proof.UserID || user.Email != proof.Email || user.TokenVersion != proof.TokenVersion ||
			user.Status != domain.UserStatusActive || !passwordCredentialEligible(user) {
			return nil, domain.ErrInvalidOob
		}
		return user, nil
	}
	email, err := s.repo.ConsumeOobCode(ctx, code, request)
	if err != nil {
		return nil, err
	}
	user, err := s.repo.FindByEmail(ctx, email)
	if err != nil || user == nil {
		if request == "EMAIL_SIGNIN" {
			return nil, domain.ErrInvalidCreds
		}
		return nil, domain.ErrNotFound
	}
	return user, nil
}
