package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
	"strings"
	"testing"
	"time"
)

type trinoTestAuthority struct {
	principal domain.TrinoPrincipal
	err       error
	user      string
	workload  domain.WorkloadSubject
	calls     int
}

func (a *trinoTestAuthority) AuthorizeUser(_ context.Context, installation, tenant, uid string) (domain.TrinoPrincipal, error) {
	a.calls++
	a.user = uid
	return a.principal, a.err
}
func (a *trinoTestAuthority) AuthorizeWorkload(_ context.Context, installation, tenant string, subject domain.WorkloadSubject) (domain.TrinoPrincipal, error) {
	a.calls++
	a.workload = subject
	return a.principal, a.err
}
func trinoFixturePrincipal(kind string) domain.TrinoPrincipal {
	return domain.TrinoPrincipal{InstallationUID: "installation-1", TenantID: "tenant-1", TenantEpoch: strings.Repeat("a", 64), SubjectKind: kind, SubjectUID: "user-1"}
}
func trinoUserFixture(t *testing.T, a TrinoIdentityAuthority) (*userService, domain.TokenExchangeReq) {
	t.Helper()
	tenant := "tenant-1"
	u := &domain.User{Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive, Role: domain.RoleCompanyEmployee, CompanyId: &tenant}
	repo := &mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return u, nil }}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://issuer", "tikti", makePEMKey(t), "kid", WithTrinoIdentityAuthority(a)).(*userService)
	req := domain.TokenExchangeReq{IdToken: signCurrentIDToken(t, "secret", u.Email, "https://issuer", "tikti", 0), Audience: "trino:installation-1", TenantID: tenant, Scopes: []string{domain.TrinoQueryScope}}
	return svc, req
}
func TestPlatformDataAccessUserIssuance(t *testing.T) {
	a := &trinoTestAuthority{principal: trinoFixturePrincipal("User")}
	s, req := trinoUserFixture(t, a)
	req.TTLSeconds = 86400
	r, err := s.TokenExchange(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := s.getRSAPrivateKey()
	claims, err := utils.ValidateRS256(r.AccessToken, &key.(*rsa.PrivateKey).PublicKey, "https://issuer", req.Audience)
	if err != nil {
		t.Fatal(err)
	}
	opaque, _ := a.principal.OpaquePrincipal()
	if r.ExpiresIn != 300 || claims["trino_principal"] != opaque || claims["sub"] != "user-1" || claims["scope"] != domain.TrinoQueryScope || a.user != "user-1" {
		t.Fatal("wrong signed identity")
	}
	if _, ok := claims["role"]; ok {
		t.Fatal("legacy authority leaked")
	}
}
func TestPlatformDataAccessUserDenials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*domain.TokenExchangeReq, *trinoTestAuthority)
	}{
		{"scope", func(r *domain.TokenExchangeReq, a *trinoTestAuthority) { r.Scopes = []string{"codeq:admin"} }},
		{"empty scope", func(r *domain.TokenExchangeReq, a *trinoTestAuthority) { r.Scopes = nil }},
		{"duplicate scope", func(r *domain.TokenExchangeReq, a *trinoTestAuthority) { r.Scopes = append(r.Scopes, r.Scopes[0]) }},
		{"malformed audience", func(r *domain.TokenExchangeReq, a *trinoTestAuthority) { r.Audience = "trino:" }},
		{"foreign installation", func(r *domain.TokenExchangeReq, a *trinoTestAuthority) { a.principal.InstallationUID = "other" }},
		{"foreign tenant", func(r *domain.TokenExchangeReq, a *trinoTestAuthority) { a.principal.TenantID = "other" }},
		{"foreign user", func(r *domain.TokenExchangeReq, a *trinoTestAuthority) { a.principal.SubjectUID = "other" }},
		{"wrong kind", func(r *domain.TokenExchangeReq, a *trinoTestAuthority) { a.principal.SubjectKind = "Service" }},
		{"retired", func(r *domain.TokenExchangeReq, a *trinoTestAuthority) { a.err = domain.ErrUnauthorizedScope }},
		{"outage", func(r *domain.TokenExchangeReq, a *trinoTestAuthority) { a.err = errors.New("private provider error") }},
		{"discovery", func(r *domain.TokenExchangeReq, a *trinoTestAuthority) { r.DiscoverTenantTargetsV1 = true }},
		{"events", func(r *domain.TokenExchangeReq, a *trinoTestAuthority) { r.EventTypes = []string{"event"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &trinoTestAuthority{principal: trinoFixturePrincipal("User")}
			s, r := trinoUserFixture(t, a)
			tc.mutate(&r, a)
			if out, err := s.TokenExchange(context.Background(), r); err == nil || out != nil {
				t.Fatal("accepted unauthorized exchange")
			}
		})
	}
	s, r := trinoUserFixture(t, nil)
	if out, err := s.TokenExchange(context.Background(), r); err == nil || out != nil {
		t.Fatal("nil authority fell through to legacy")
	}
}
func TestPlatformDataAccessWorkloadIssuance(t *testing.T) {
	key, pem := workloadTestKey(t)
	a := &trinoTestAuthority{principal: trinoFixturePrincipal("Service")}
	a.principal.SubjectUID = "service-uid"
	s := NewWorkloadIdentityService(nil, trinoWorkloadVerifier(), "https://issuer", pem, "kid", time.Hour, WithWorkloadTrinoIdentityAuthority(a))
	req := domain.WorkloadTokenExchangeReq{SubjectToken: "projected", SubjectTokenType: domain.WorkloadSubjectTokenType, Audience: "trino:installation-1", TenantID: "tenant-1", Scopes: []string{domain.TrinoQueryScope}}
	r, err := s.Exchange(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := utils.ValidateRS256(r.AccessToken, &key.PublicKey, "https://issuer", req.Audience)
	if err != nil {
		t.Fatal(err)
	}
	opaque, _ := a.principal.OpaquePrincipal()
	if r.ExpiresIn != 300 || claims["trino_principal"] != opaque || a.workload.Subject != testWorkloadSubject {
		t.Fatal("wrong workload identity")
	}
	for _, change := range []func(){func() { a.principal.SubjectKind = "User" }, func() { a.principal = trinoFixturePrincipal("Service"); a.principal.TenantID = "other" }, func() { a.principal = trinoFixturePrincipal("Service"); a.err = errors.New("outage") }} {
		change()
		if out, err := s.Exchange(context.Background(), req); err == nil || out != nil {
			t.Fatal("invalid workload authority accepted")
		}
	}
	off := NewWorkloadIdentityService(nil, trinoWorkloadVerifier(), "https://issuer", pem, "kid", time.Hour)
	if out, err := off.Exchange(context.Background(), req); err == nil || out != nil {
		t.Fatal("default not off")
	}
}

func trinoWorkloadVerifier() *fakeWorkloadVerifier {
	v := validWorkloadVerifier()
	v.subject.Issuer = "https://cluster.example"
	v.subject.ClusterRef = "cluster-1"
	return v
}

func TestPlatformDataAccessLegacyTokensUnchanged(t *testing.T) {
	a := &trinoTestAuthority{err: errors.New("must not be called")}
	s, req := trinoUserFixture(t, a)
	req.Audience = "legacy-custom"
	req.Scopes = nil
	r, err := s.TokenExchange(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := s.getRSAPrivateKey()
	claims, err := utils.ValidateRS256(r.AccessToken, &key.(*rsa.PrivateKey).PublicKey, "https://issuer", req.Audience)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := claims["trino_principal"]; ok || r.ExpiresIn != 3600 || a.calls != 0 {
		t.Fatal("legacy user contract changed")
	}
	wk, pem := workloadTestKey(t)
	w := NewWorkloadIdentityService(&memoryWorkloadBindingRepo{binding: validWorkloadBinding()}, validWorkloadVerifier(), "https://issuer", pem, "kid", time.Hour, WithWorkloadTrinoIdentityAuthority(a))
	wr, err := w.Exchange(context.Background(), validWorkloadExchangeRequest())
	if err != nil {
		t.Fatal(err)
	}
	wc, err := utils.ValidateRS256(wr.AccessToken, &wk.PublicKey, "https://issuer", domain.WorkloadTargetAudience)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := wc["trino_principal"]; ok || wr.ExpiresIn != 3600 || a.calls != 0 {
		t.Fatal("legacy workload contract changed")
	}
}

func TestPlatformDataAccessWorkloadRejectsIncompleteAttestation(t *testing.T) {
	_, pem := workloadTestKey(t)
	for _, change := range []func(*fakeWorkloadVerifier){func(v *fakeWorkloadVerifier) { v.err = domain.ErrWorkloadTokenInvalid }, func(v *fakeWorkloadVerifier) { v.subject.Issuer = "" }, func(v *fakeWorkloadVerifier) { v.subject.ClusterRef = "" }, func(v *fakeWorkloadVerifier) { v.subject.Namespace = "other" }, func(v *fakeWorkloadVerifier) { v.subject.Subject = "arbitrary" }} {
		a := &trinoTestAuthority{principal: trinoFixturePrincipal("Service")}
		v := trinoWorkloadVerifier()
		change(v)
		s := NewWorkloadIdentityService(nil, v, "https://issuer", pem, "kid", time.Hour, WithWorkloadTrinoIdentityAuthority(a))
		req := domain.WorkloadTokenExchangeReq{SubjectToken: "projected", SubjectTokenType: domain.WorkloadSubjectTokenType, Audience: "trino:installation-1", TenantID: "tenant-1", Scopes: []string{domain.TrinoQueryScope}}
		if r, err := s.Exchange(context.Background(), req); err == nil || r != nil || a.calls != 0 {
			t.Fatal("unverified subject reached authority")
		}
	}
}

func TestPlatformDataAccessUserSourceExpiryAndReservedAudience(t *testing.T) {
	a := &trinoTestAuthority{principal: trinoFixturePrincipal("User")}
	s, r := trinoUserFixture(t, a)
	token, _, err := jwt.NewParser().ParseUnverified(r.IdToken, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(40 * time.Second).Unix()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	r.IdToken = signed
	result, err := s.TokenExchange(context.Background(), r)
	if err != nil || result.ExpiresIn > 40 || result.ExpiresIn < 1 {
		t.Fatal("Trino expiry exceeded source")
	}
	for _, aud := range []string{"trino:", " trino:installation-1", "TRINO:installation-1", "trino:installation-1\n", "trino:installation:other"} {
		r.Audience = aud
		if result, err := s.TokenExchange(context.Background(), r); err == nil || result != nil {
			t.Fatal("reserved audience escaped validation")
		}
	}
}

func TestPlatformDataAccessSigningAndLifetimeFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*userService, *trinoTestAuthority, jwt.MapClaims)
	}{
		{"missing expiry", func(s *userService, a *trinoTestAuthority, c jwt.MapClaims) { delete(c, "exp") }},
		{"expired during authorization", func(s *userService, a *trinoTestAuthority, c jwt.MapClaims) {
			c["exp"] = float64(time.Now().Add(-time.Minute).Unix())
		}},
		{"invalid authentication methods", func(s *userService, a *trinoTestAuthority, c jwt.MapClaims) { c["amr"] = 42 }},
		{"invalid authority epoch", func(s *userService, a *trinoTestAuthority, c jwt.MapClaims) { a.principal.TenantEpoch = "invalid" }},
		{"empty issuer", func(s *userService, a *trinoTestAuthority, c jwt.MapClaims) { s.issuerBaseURL = "" }},
		{"missing key id", func(s *userService, a *trinoTestAuthority, c jwt.MapClaims) { s.jwksKeyID = "" }},
		{"bad signing key", func(s *userService, a *trinoTestAuthority, c jwt.MapClaims) { s.jwksPrivateKey = "invalid" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &trinoTestAuthority{principal: trinoFixturePrincipal("User")}
			s, r := trinoUserFixture(t, a)
			c := jwt.MapClaims{"exp": float64(time.Now().Add(time.Hour).Unix())}
			tc.change(s, a, c)
			out, err := s.exchangeTrinoUser(context.Background(), r, &domain.User{Id: "user-1"}, c)
			if err == nil || out != nil {
				t.Fatal("invalid signing/lifetime accepted")
			}
		})
	}
	a := &trinoTestAuthority{principal: trinoFixturePrincipal("User")}
	s, r := trinoUserFixture(t, a)
	r.TTLSeconds = 10
	c := jwt.MapClaims{"exp": float64(time.Now().Add(time.Hour).Unix()), "amr": []string{"pwd"}}
	out, err := s.exchangeTrinoUser(context.Background(), r, &domain.User{Id: "user-1"}, c)
	if err != nil || out.ExpiresIn != 10 {
		t.Fatal("short TTL/authentication method rejected")
	}
}

func TestPlatformDataAccessWorkloadKeyUnavailable(t *testing.T) {
	a := &trinoTestAuthority{principal: trinoFixturePrincipal("Service")}
	s := NewWorkloadIdentityService(nil, trinoWorkloadVerifier(), "https://issuer", "invalid", "kid", time.Minute, WithWorkloadTrinoIdentityAuthority(a))
	r := domain.WorkloadTokenExchangeReq{SubjectToken: "projected", SubjectTokenType: domain.WorkloadSubjectTokenType, Audience: "trino:installation-1", TenantID: "tenant-1", Scopes: []string{domain.TrinoQueryScope}}
	if out, err := s.Exchange(context.Background(), r); !errors.Is(err, domain.ErrWorkloadIdentityUnavailable) || out != nil {
		t.Fatal("unavailable key accepted")
	}
}
