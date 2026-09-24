package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type scopeStore struct {
	targetCompany string
	linked        bool
}

func (f scopeStore) HGet(_ context.Context, key, field string) *redis.StringCmd {
	switch {
	case key == "users_v2" && field == "fernando":
		return redis.NewStringResult(`{"role":"COMPANY_ADMIN","status":"ACTIVE"}`, nil)
	case key == "users_v2" && field == "employee":
		return redis.NewStringResult(`{"email":"employee@conveste.test","role":"COMPANY_EMPLOYEE","status":"ACTIVE","companyId":"`+f.targetCompany+`"}`, nil)
	case key == "companies":
		admin := "other"
		if f.linked {
			admin = "fernando"
		}
		return redis.NewStringResult(`{"adminUserId":"`+admin+`","status":"active"}`, nil)
	}
	return redis.NewStringResult("", redis.Nil)
}
func (scopeStore) Get(_ context.Context, key string) *redis.StringCmd {
	if key == "userByEmail:employee@conveste.test" {
		return redis.NewStringResult("employee", nil)
	}
	return redis.NewStringResult("", redis.Nil)
}

func testAdminToken(t *testing.T) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"userId": "fernando", "role": "COMPANY_ADMIN"})
	signed, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestCompanyAdminMembershipRequiresLinkedActorAndOwnEmployee(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, targetCompany string
		linked              bool
		roles               []string
		want                bool
	}{
		{"own employee", convesteCompanyID, true, []string{"PULSE_WRITER", "COMPANY_EMPLOYEE"}, true},
		{"unlinked admin", convesteCompanyID, false, []string{"COMPANY_EMPLOYEE"}, false},
		{"other company employee", "other", true, []string{"COMPANY_EMPLOYEE"}, false},
		{"role escalation", convesteCompanyID, true, []string{"ADMIN"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/tenants/default/users", nil)
			ctx.Request.Header.Set("Authorization", "Bearer "+testAdminToken(t))
			got := allowConvesteMembership(ctx, &config.Config{JwtSecret: "secret"}, scopeStore{targetCompany: tc.targetCompany, linked: tc.linked}, "default", domain.MembershipCreateReq{Email: "employee@conveste.test", Roles: tc.roles})
			if got != tc.want {
				t.Fatalf("got %t, want %t", got, tc.want)
			}
		})
	}
}
