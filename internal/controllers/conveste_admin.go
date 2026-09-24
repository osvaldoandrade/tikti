package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const convesteCompanyID = "c11d3441-52a9-47b0-ba26-48ecc9350b01"

type identityStore interface {
	HGet(context.Context, string, string) *redis.StringCmd
	Get(context.Context, string) *redis.StringCmd
}

// linkedConvesteAdmin checks current persisted authority, not just JWT claims.
func linkedConvesteAdmin(ctx context.Context, client identityStore, actorID string) (bool, error) {
	if actorID == "" || client == nil {
		return false, nil
	}
	raw, err := client.HGet(ctx, "users_v2", actorID).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var actor struct {
		Role   string `json:"role"`
		Status string `json:"status"`
	}
	if json.Unmarshal([]byte(raw), &actor) != nil || actor.Role != "COMPANY_ADMIN" || actor.Status != "ACTIVE" {
		return false, nil
	}
	raw, err = client.HGet(ctx, "companies", convesteCompanyID).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var company struct {
		AdminUserID string `json:"adminUserId"`
		Status      string `json:"status"`
	}
	if json.Unmarshal([]byte(raw), &company) != nil {
		return false, nil
	}
	return company.AdminUserID == actorID && strings.EqualFold(company.Status, "active"), nil
}

func allowConvesteMembership(c *gin.Context, cfg *config.Config, client identityStore, tenantID string, req domain.MembershipCreateReq) bool {
	token := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
	claims, err := utils.ParseToken(token, cfg.JwtSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return false
	}
	role, _ := claims["role"].(string)
	if role == "ADMIN" {
		return true
	}
	actorID, _ := claims["userId"].(string)
	allowed, err := linkedConvesteAdmin(c.Request.Context(), client, actorID)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "authorization unavailable"})
		return false
	}
	if role != "COMPANY_ADMIN" || !allowed || tenantID != "default" {
		c.JSON(http.StatusForbidden, gin.H{"error": "company admin membership forbidden"})
		return false
	}
	if len(req.Roles) == 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "role required"})
		return false
	}
	for _, item := range req.Roles {
		if item != "PULSE_WRITER" && item != "COMPANY_EMPLOYEE" {
			c.JSON(http.StatusForbidden, gin.H{"error": "role forbidden"})
			return false
		}
	}
	email := strings.TrimSpace(req.Email)
	userID, err := client.Get(c.Request.Context(), "userByEmail:"+email).Result()
	if errors.Is(err, redis.Nil) && email != strings.ToLower(email) {
		userID, err = client.Get(c.Request.Context(), "userByEmail:"+strings.ToLower(email)).Result()
	}
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "user not linked to Conveste"})
		return false
	}
	raw, err := client.HGet(c.Request.Context(), "users_v2", userID).Result()
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "user not linked to Conveste"})
		return false
	}
	var target struct {
		Email     string `json:"email"`
		Role      string `json:"role"`
		Status    string `json:"status"`
		CompanyID string `json:"companyId"`
	}
	if json.Unmarshal([]byte(raw), &target) != nil || !strings.EqualFold(strings.TrimSpace(target.Email), strings.TrimSpace(req.Email)) || target.CompanyID != convesteCompanyID || target.Role != "COMPANY_EMPLOYEE" || target.Status != "ACTIVE" {
		c.JSON(http.StatusForbidden, gin.H{"error": "user not linked to Conveste"})
		return false
	}
	return true
}
