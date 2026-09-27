package app

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/osvaldoandrade/tikti/internal/services"
	"net/http/httptest"
	"testing"
)

type topicRouteService struct {
	services.WorkloadIdentityService
	calls int
}

func (s *topicRouteService) ValidateCodeQTopicToken(context.Context, string) (services.CodeQTopicAuthority, error) {
	s.calls++
	return services.CodeQTopicAuthority{SchemaVersion: "codeq-topic-authority/v1", TenantID: "payments", TenantEpoch: "test-epoch", Active: true}, nil
}
func TestCodeQTopicAuthorityRejectsBrowserAndAmbiguousRequests(t *testing.T) {
	s := &topicRouteService{}
	e := gin.New()
	setupCodeQTopicAuthority(e, s)
	for _, scenario := range []string{"valid", "duplicate", "origin", "cookie", "query", "post"} {
		t.Run(scenario, func(t *testing.T) {
			method, path := "GET", codeQTopicAuthorityPath
			if scenario == "post" {
				method = "POST"
			}
			if scenario == "query" {
				path += "?tenant=foreign"
			}
			r := httptest.NewRequest(method, path, nil)
			r.Header.Set("Authorization", "Bearer test-only")
			switch scenario {
			case "duplicate":
				r.Header.Add("Authorization", "Bearer second")
			case "origin":
				r.Header.Set("Origin", "https://browser")
			case "cookie":
				r.Header.Set("Cookie", "session=x")
			}
			before := s.calls
			w := httptest.NewRecorder()
			e.ServeHTTP(w, r)
			if scenario == "valid" {
				if w.Code != 200 || s.calls != before+1 || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("valid request failed")
				}
			} else if w.Code == 200 || s.calls != before {
				t.Fatal("ambiguous request reached authority")
			}
		})
	}
}
