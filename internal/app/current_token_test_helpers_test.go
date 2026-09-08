package app

import (
	"context"

	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

type testCurrentAdminTokenService struct {
	services.UserService
	config *config.Config
}

func (s testCurrentAdminTokenService) ValidateAccessToken(_ context.Context, token, issuer, audience string) (jwt.MapClaims, error) {
	key, err := utils.ParseRSAPrivateKey(s.config.JwksPrivateKey)
	if err != nil {
		return nil, err
	}
	return utils.ValidateRS256(token, &key.PublicKey, issuer, audience)
}
