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
	companyID     string
	targetCompany string
	linked        bool
}

func (f scopeStore) HGet(_ context.Context, key, field string) *redis.StringCmd {
	switch {
	case key == "users_v2" && field == "fernando":
		return redis.NewStringResult(`{"role":"COMPANY_ADMIN","status":"ACTIVE"}`, nil)
	case key == "users_v2" && field == "employee":
		return redis.NewStringResult(`{"email":"employee@conveste.test","role":"COMPANY_EMPLOYEE","status":"ACTIVE","companyId":"`+f.targetCompany+`"}`, nil)
	}
	return redis.NewStringResult("", redis.Nil)
}
func (f scopeStore) HGetAll(_ context.Context, key string) *redis.StringStringMapCmd {
	if key != "companies" {
		return redis.NewStringStringMapResult(nil, redis.Nil)
	}
	admin := "other"
	if f.linked {
		admin = "fernando"
	}
	return redis.NewStringStringMapResult(map[string]string{f.companyID: `{"adminUserId":"` + admin + `","status":"active"}`}, nil)
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
		name, companyID, targetCompany string
		linked                         bool
		roles                          []string
		want                           bool
	}{
		{"Conveste employee", "conveste", "conveste", true, []string{"PULSE_WRITER", "COMPANY_EMPLOYEE"}, true},
		{"Certiface employee", "certiface", "certiface", true, []string{"COMPANY_EMPLOYEE"}, true},
		{"unlinked admin", "conveste", "conveste", false, []string{"COMPANY_EMPLOYEE"}, false},
		{"other company employee", "conveste", "certiface", true, []string{"COMPANY_EMPLOYEE"}, false},
		{"role escalation", "conveste", "conveste", true, []string{"ADMIN"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/tenants/default/users", nil)
			ctx.Request.Header.Set("Authorization", "Bearer "+testAdminToken(t))
			got := allowCompanyAdminMembership(ctx, &config.Config{JwtSecret: "secret"}, scopeStore{companyID: tc.companyID, targetCompany: tc.targetCompany, linked: tc.linked}, "default", domain.MembershipCreateReq{Email: "employee@conveste.test", Roles: tc.roles})
			if got != tc.want {
				t.Fatalf("got %t, want %t", got, tc.want)
			}
		})
	}
}
