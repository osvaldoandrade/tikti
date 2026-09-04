package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type userAdminController struct {
	svc services.UserService
	cfg *config.Config
}

func NewUserAdminController(svc services.UserService, cfg *config.Config) *userAdminController {
	return &userAdminController{svc: svc, cfg: cfg}
}

type statusReq struct {
	Email  string `json:"email"`
	Status string `json:"status"`
}

type revokeReq struct {
	Email    string `json:"email"`
	TenantId string `json:"tenantId,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

const globalRevocationOnlyMessage = "only global token revocation is supported; omit tenantId and use scope=global"

const revokeBodyLimit = 16 << 10

func (u *userAdminController) SetStatus(c *gin.Context) {
	if !requireAdmin(c, u.cfg) {
		return
	}
	var req statusReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return u.svc.SetStatus(ctx, req.Email, req.Status)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case domain.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

func (u *userAdminController) Revoke(c *gin.Context) {
	if !requireAdmin(c, u.cfg) {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, revokeBodyLimit)
	req, err := decodeRevokeRequest(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	tenantID := strings.TrimSpace(req.TenantId)
	scope := strings.ToLower(strings.TrimSpace(req.Scope))
	if tenantID != "" || scope != "" && scope != "global" {
		c.JSON(http.StatusBadRequest, gin.H{"error": globalRevocationOnlyMessage})
		return
	}
	if scope == "" {
		scope = "global"
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return u.svc.RevokeTokens(ctx, req.Email, "", scope)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case domain.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

func decodeRevokeRequest(body io.Reader) (revokeReq, error) {
	decoder := json.NewDecoder(body)
	if err := expectJSONDelimiter(decoder, '{'); err != nil {
		return revokeReq{}, err
	}

	var req revokeReq
	seen := make(map[string]struct{}, 3)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return revokeReq{}, err
		}
		key, ok := token.(string)
		if !ok {
			return revokeReq{}, domain.ErrInvalidArgument
		}
		if _, duplicate := seen[key]; duplicate {
			return revokeReq{}, domain.ErrInvalidArgument
		}
		seen[key] = struct{}{}

		switch key {
		case "email":
			err = decoder.Decode(&req.Email)
		case "tenantId":
			err = decoder.Decode(&req.TenantId)
		case "scope":
			err = decoder.Decode(&req.Scope)
		default:
			return revokeReq{}, domain.ErrInvalidArgument
		}
		if err != nil {
			return revokeReq{}, err
		}
	}

	if err := expectJSONDelimiter(decoder, '}'); err != nil {
		return revokeReq{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return revokeReq{}, domain.ErrInvalidArgument
	}
	return req, nil
}
