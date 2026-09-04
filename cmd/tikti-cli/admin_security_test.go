package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestCLIProductionSourcesDoNotEmbedQueryAPIKeys(t *testing.T) {
	for _, path := range []string{"main.go", "saml_idp_update.go"} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(contents), "?key=") {
			t.Fatalf("%s still places API credentials in query strings", path)
		}
	}
}

func TestLegacyReadCommandsUseHeaderAPIKeyAndScopedAccessToken(t *testing.T) {
	tests := []struct {
		name string
		path string
		run  func(*string, *bool) error
	}{
		{name: "tenant get", path: "/v1/tenants/id/bereia", run: func(profile *string, outputJSON *bool) error {
			command := tenantCmd(profile, outputJSON)
			command.SetArgs([]string{"get", "--tenant", "bereia"})
			return command.Execute()
		}},
		{name: "role list", path: "/v1/tenants/bereia/roles", run: func(profile *string, outputJSON *bool) error {
			command := roleCmd(profile, outputJSON)
			command.SetArgs([]string{"list", "--tenant", "bereia"})
			return command.Execute()
		}},
		{name: "client list", path: "/v1/tenants/bereia/clients", run: func(profile *string, outputJSON *bool) error {
			command := clientCmd(profile, outputJSON)
			command.SetArgs([]string{"list", "--tenant", "bereia"})
			return command.Execute()
		}},
		{name: "client get", path: "/v1/tenants/bereia/clients/code-admin-api", run: func(profile *string, outputJSON *bool) error {
			command := clientCmd(profile, outputJSON)
			command.SetArgs([]string{"get", "--tenant", "bereia", "--client-id", "code-admin-api"})
			return command.Execute()
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requestCount++
				if req.URL.Path != test.path || req.URL.RawQuery != "" {
					t.Errorf("request URL = %s?%s, want %s", req.URL.Path, req.URL.RawQuery, test.path)
				}
				if req.Header.Get("X-API-Key") != "api-key" {
					t.Errorf("X-API-Key = %q", req.Header.Get("X-API-Key"))
				}
				if req.Header.Get("Authorization") != "Bearer scoped-access-token" {
					t.Errorf("Authorization = %q", req.Header.Get("Authorization"))
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()

			original := loadProfileFunc
			loadProfileFunc = func(string) (*profileEntry, error) {
				return &profileEntry{
					BaseURL: server.URL, ApiKey: "api-key", TenantId: "bereia",
					IdToken: "legacy-id-token", AccessToken: "scoped-access-token",
				}, nil
			}
			defer func() { loadProfileFunc = original }()

			profile, outputJSON := "", true
			if err := test.run(&profile, &outputJSON); err != nil {
				t.Fatalf("execute command: %v", err)
			}
			if requestCount != 1 {
				t.Fatalf("request count = %d, want 1", requestCount)
			}
		})
	}
}

func TestLegacyReadCommandsFailLocallyWithoutScopedAccessToken(t *testing.T) {
	tests := []struct {
		name string
		run  func(*string, *bool) error
	}{
		{name: "tenant get", run: func(profile *string, outputJSON *bool) error {
			command := tenantCmd(profile, outputJSON)
			command.SetArgs([]string{"get", "--tenant", "bereia"})
			return command.Execute()
		}},
		{name: "role list", run: func(profile *string, outputJSON *bool) error {
			command := roleCmd(profile, outputJSON)
			command.SetArgs([]string{"list", "--tenant", "bereia"})
			return command.Execute()
		}},
		{name: "client list", run: func(profile *string, outputJSON *bool) error {
			command := clientCmd(profile, outputJSON)
			command.SetArgs([]string{"list", "--tenant", "bereia"})
			return command.Execute()
		}},
		{name: "client get", run: func(profile *string, outputJSON *bool) error {
			command := clientCmd(profile, outputJSON)
			command.SetArgs([]string{"get", "--tenant", "bereia", "--client-id", "code-admin-api"})
			return command.Execute()
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requestCount++ }))
			defer server.Close()

			original := loadProfileFunc
			loadProfileFunc = func(string) (*profileEntry, error) {
				return &profileEntry{
					BaseURL: server.URL, ApiKey: "api-key", TenantId: "bereia", IdToken: "legacy-id-token",
				}, nil
			}
			defer func() { loadProfileFunc = original }()

			profile, outputJSON := "", true
			err := test.run(&profile, &outputJSON)
			if err == nil || !strings.Contains(err.Error(), "scoped access token") {
				t.Fatalf("error = %v, want scoped access token guidance", err)
			}
			if requestCount != 0 {
				t.Fatalf("unsafe request count = %d", requestCount)
			}
		})
	}
}

func TestMembershipCommandUsesHeaderAPIKeyAndScopedAccessToken(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requestCount++
		if req.URL.Path != "/v1/tenants/bereia/users" || req.URL.RawQuery != "" {
			t.Errorf("request URL = %s?%s", req.URL.Path, req.URL.RawQuery)
		}
		if req.Header.Get("X-API-Key") != "api-key" {
			t.Errorf("X-API-Key = %q", req.Header.Get("X-API-Key"))
		}
		if req.Header.Get("Authorization") != "Bearer scoped-access-token" {
			t.Errorf("Authorization = %q", req.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tenantId":"bereia","email":"u@example.com"}`))
	}))
	defer server.Close()

	original := loadProfileFunc
	loadProfileFunc = func(string) (*profileEntry, error) {
		return &profileEntry{
			BaseURL: server.URL, ApiKey: "api-key", TenantId: "bereia",
			IdToken: "legacy-id-token", AccessToken: "scoped-access-token",
		}, nil
	}
	t.Cleanup(func() { loadProfileFunc = original })

	profile, outputJSON := "", true
	command := membershipCmd(&profile, &outputJSON)
	command.SetArgs([]string{"add", "--email", "u@example.com", "--roles", "reader"})
	if err := command.Execute(); err != nil {
		t.Fatalf("membership add: %v", err)
	}
	if requestCount != 1 {
		t.Fatalf("request count = %d, want 1", requestCount)
	}
}

func TestMembershipCommandFailsLocallyWithoutScopedAccessToken(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requestCount++ }))
	defer server.Close()

	original := loadProfileFunc
	loadProfileFunc = func(string) (*profileEntry, error) {
		return &profileEntry{BaseURL: server.URL, ApiKey: "api-key", TenantId: "bereia", IdToken: "legacy-id-token"}, nil
	}
	t.Cleanup(func() { loadProfileFunc = original })

	profile, outputJSON := "", true
	command := membershipCmd(&profile, &outputJSON)
	command.SetArgs([]string{"remove", "--email", "u@example.com"})
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "scoped access token") {
		t.Fatalf("error = %v, want scoped access token guidance", err)
	}
	if requestCount != 0 {
		t.Fatalf("unsafe request count = %d", requestCount)
	}
}

func TestRevokeCommandRejectsUnsupportedTenantSemanticsLocally(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requestCount++ }))
	defer server.Close()

	original := loadProfileFunc
	loadProfileFunc = func(string) (*profileEntry, error) {
		return &profileEntry{BaseURL: server.URL, ApiKey: "api-key", IdToken: "legacy-id-token"}, nil
	}
	t.Cleanup(func() { loadProfileFunc = original })

	profile, outputJSON := "", true
	command := revokeCmd(&profile, &outputJSON)
	command.SetArgs([]string{"tokens", "--email", "u@example.com", "--tenant", "bereia", "--scope", "tenant"})
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "global revocation") {
		t.Fatalf("error = %v, want global revocation guidance", err)
	}
	if requestCount != 0 {
		t.Fatalf("unsupported revocation reached server %d times", requestCount)
	}
}

func TestRevokeCommandUsesExplicitGlobalContractAndHeaderAPIKey(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requestCount++
		if req.URL.Path != "/v1/accounts/revoke" || req.URL.RawQuery != "" {
			t.Errorf("request URL = %s?%s", req.URL.Path, req.URL.RawQuery)
		}
		if req.Header.Get("X-API-Key") != "api-key" || req.Header.Get("Authorization") != "Bearer scoped-access-token" {
			t.Errorf("request headers = %v", req.Header)
		}
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if body["email"] != "u@example.com" || body["scope"] != "global" {
			t.Errorf("request body = %#v", body)
		}
		if _, present := body["tenantId"]; present {
			t.Errorf("tenantId must be absent: %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"email":"u@example.com","tokenVersion":2}`))
	}))
	defer server.Close()

	original := loadProfileFunc
	loadProfileFunc = func(string) (*profileEntry, error) {
		return &profileEntry{BaseURL: server.URL, ApiKey: "api-key", IdToken: "legacy-id-token", AccessToken: "scoped-access-token"}, nil
	}
	t.Cleanup(func() { loadProfileFunc = original })

	profile, outputJSON := "", true
	command := revokeCmd(&profile, &outputJSON)
	command.SetArgs([]string{"tokens", "--email", "u@example.com", "--scope", "global"})
	if err := command.Execute(); err != nil {
		t.Fatalf("global revoke: %v", err)
	}
	if requestCount != 1 {
		t.Fatalf("request count = %d, want 1", requestCount)
	}
}

func TestAdminMutationCommandsUseHeaderAPIKeyAndScopedAccessToken(t *testing.T) {
	tests := []struct {
		name, path string
		run        func(*string, *bool) error
	}{
		{name: "user create", path: "/v1/accounts/signUp", run: func(profile *string, outputJSON *bool) error {
			command := userCmd(profile, outputJSON)
			command.SetArgs([]string{"create", "--email", "u@example.com", "--password", "password"})
			return command.Execute()
		}},
		{name: "user suspend", path: "/v1/accounts/status", run: func(profile *string, outputJSON *bool) error {
			command := userCmd(profile, outputJSON)
			command.SetArgs([]string{"suspend", "--email", "u@example.com"})
			return command.Execute()
		}},
		{name: "tenant create", path: "/v1/tenants", run: func(profile *string, outputJSON *bool) error {
			command := tenantCmd(profile, outputJSON)
			command.SetArgs([]string{"create", "--name", "Bereia", "--slug", "bereia"})
			return command.Execute()
		}},
		{name: "role create", path: "/v1/tenants/bereia/roles", run: func(profile *string, outputJSON *bool) error {
			command := roleCmd(profile, outputJSON)
			command.SetArgs([]string{"create", "--tenant", "bereia", "--name", "reader", "--permissions", "read"})
			return command.Execute()
		}},
		{name: "client create", path: "/v1/tenants/bereia/clients", run: func(profile *string, outputJSON *bool) error {
			command := clientCmd(profile, outputJSON)
			command.SetArgs([]string{"create", "--tenant", "bereia", "--client-id", "worker"})
			return command.Execute()
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				calls++
				if request.URL.Path != test.path || request.URL.RawQuery != "" {
					t.Errorf("request URL = %s?%s, want %s", request.URL.Path, request.URL.RawQuery, test.path)
				}
				if request.Header.Get("X-API-Key") != "api-key" || request.Header.Get("Authorization") != "Bearer scoped-access-token" {
					t.Errorf("request headers = %v", request.Header)
				}
				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write([]byte(`{}`))
			}))
			defer server.Close()

			original := loadProfileFunc
			loadProfileFunc = func(string) (*profileEntry, error) {
				return &profileEntry{BaseURL: server.URL, ApiKey: "api-key", TenantId: "bereia", IdToken: "legacy-id-token", AccessToken: "scoped-access-token"}, nil
			}
			defer func() { loadProfileFunc = original }()

			profile, outputJSON := "", true
			if err := test.run(&profile, &outputJSON); err != nil {
				t.Fatalf("execute command: %v", err)
			}
			if calls != 1 {
				t.Fatalf("request count = %d, want 1", calls)
			}
		})
	}
}

func TestAdminMutationCommandsFailLocallyWithoutScopedAccessToken(t *testing.T) {
	tests := []struct {
		name string
		run  func(*string, *bool) error
	}{
		{name: "user create", run: func(profile *string, outputJSON *bool) error {
			command := userCmd(profile, outputJSON)
			command.SetArgs([]string{"create", "--email", "u@example.com", "--password", "password"})
			return command.Execute()
		}},
		{name: "user suspend", run: func(profile *string, outputJSON *bool) error {
			command := userCmd(profile, outputJSON)
			command.SetArgs([]string{"suspend", "--email", "u@example.com"})
			return command.Execute()
		}},
		{name: "tenant create", run: func(profile *string, outputJSON *bool) error {
			command := tenantCmd(profile, outputJSON)
			command.SetArgs([]string{"create", "--name", "Bereia", "--slug", "bereia"})
			return command.Execute()
		}},
		{name: "role create", run: func(profile *string, outputJSON *bool) error {
			command := roleCmd(profile, outputJSON)
			command.SetArgs([]string{"create", "--tenant", "bereia", "--name", "reader", "--permissions", "read"})
			return command.Execute()
		}},
		{name: "client create", run: func(profile *string, outputJSON *bool) error {
			command := clientCmd(profile, outputJSON)
			command.SetArgs([]string{"create", "--tenant", "bereia", "--client-id", "worker"})
			return command.Execute()
		}},
		{name: "global revoke", run: func(profile *string, outputJSON *bool) error {
			command := revokeCmd(profile, outputJSON)
			command.SetArgs([]string{"tokens", "--email", "u@example.com", "--scope", "global"})
			return command.Execute()
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
			defer server.Close()
			original := loadProfileFunc
			loadProfileFunc = func(string) (*profileEntry, error) {
				return &profileEntry{BaseURL: server.URL, ApiKey: "api-key", TenantId: "bereia", IdToken: "legacy-id-token"}, nil
			}
			defer func() { loadProfileFunc = original }()
			profile, outputJSON := "", true
			err := test.run(&profile, &outputJSON)
			if err == nil || !strings.Contains(err.Error(), "scoped access token") || calls != 0 {
				t.Fatalf("error=%v calls=%d", err, calls)
			}
		})
	}
}
