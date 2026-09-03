package config

import (
	"strings"
	"testing"
)

func TestObjectStorageBrowserDefaultsOff(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ObjectStorageBrowser.Enabled || cfg.ObjectStorageBrowser.DeleteEnabled || cfg.ObjectStorageBrowser.MaximumPresignTTLSeconds != 60 ||
		len(cfg.ObjectStorageBrowser.CohortTenants) != 0 {
		t.Fatalf("browser defaults = %#v", cfg.ObjectStorageBrowser)
	}
}

func TestObjectStorageBrowserRequiresStorageSTSAndExactBoundedCohort(t *testing.T) {
	valid := `
issuerBaseUrl: https://tikti.example.com
defaultAudience: code-admin-api
storageSTS:
  enabled: true
  syntheticAccountId: "000000000000"
  authorizerUrl: https://code-admin-api.example.com/internal/v1/object-storage:authorize
  minioStsEndpoint: http://minio.code-admin.svc:9000/
  oidcJwksUrl: http://tikti.code-admin.svc:8080/internal/v1/storage/jwks.json
  serviceSubject: tikti:object-storage-sts
  credentialTtlSeconds: 900
  serviceAssertionTtlSeconds: 60
  dependencyTimeoutSeconds: 3
  maximumConcurrent: 8
  readOnlyPolicy: code-admin-object-readonly-v1
  readWritePolicy: code-admin-object-readwrite-v1
objectStorageBrowser:
  enabled: true
  adminAuthorizerUrl: https://code-admin-api.example.com/internal/v1/object-storage/authorize-admin
  maximumPresignTtlSeconds: 60
  cohortTenants: [payments]
  deleteEnabled: true
  deleteCohortTenants: [payments]
workloadIdentity:
  issuer: https://cluster.example.com
  clusterRef: code-cloud
  audience: tikti-workload-exchange
  jwksUrl: https://cluster.example.com/jwks
`
	cfg, err := LoadConfig(writeTempConfig(t, valid))
	if err != nil || !cfg.ObjectStorageBrowser.Enabled || !cfg.ObjectStorageBrowser.DeleteEnabled || len(cfg.ObjectStorageBrowser.CohortTenants) != 1 ||
		cfg.ObjectStorageBrowser.CohortTenants[0] != "payments" {
		t.Fatalf("valid browser config=%#v err=%v", cfg, err)
	}
	for _, replacement := range []struct{ from, to string }{
		{from: "storageSTS:\n  enabled: true", to: "storageSTS:\n  enabled: false"},
		{from: "adminAuthorizerUrl: https://code-admin-api.example.com/internal/v1/object-storage/authorize-admin", to: "adminAuthorizerUrl: https://evil.example.com/other"},
		{from: "maximumPresignTtlSeconds: 60", to: "maximumPresignTtlSeconds: 61"},
		{from: "cohortTenants: [payments]", to: "cohortTenants: []"},
		{from: "cohortTenants: [payments]", to: "cohortTenants: [payments, payments]"},
		{from: "deleteCohortTenants: [payments]", to: "deleteCohortTenants: [identity]"},
	} {
		body := strings.Replace(valid, replacement.from, replacement.to, 1)
		if _, loadErr := LoadConfig(writeTempConfig(t, body)); loadErr == nil {
			t.Fatalf("unsafe browser configuration accepted: %q", replacement.to)
		}
	}
}

func TestObjectStorageBrowserAcceptsExplicitAllTenantCohortWithoutExpandingDelete(t *testing.T) {
	configuration := `
issuerBaseUrl: https://tikti.example.com
defaultAudience: code-admin-api
storageSTS:
  enabled: true
  syntheticAccountId: "000000000000"
  authorizerUrl: https://code-admin-api.example.com/internal/v1/object-storage:authorize
  minioStsEndpoint: http://minio.code-admin.svc:9000/
  oidcJwksUrl: http://tikti.code-admin.svc:8080/internal/v1/storage/jwks.json
  serviceSubject: tikti:object-storage-sts
  credentialTtlSeconds: 900
  serviceAssertionTtlSeconds: 60
  dependencyTimeoutSeconds: 3
  maximumConcurrent: 8
  readOnlyPolicy: code-admin-object-readonly-v1
  readWritePolicy: code-admin-object-readwrite-v1
objectStorageBrowser:
  enabled: true
  adminAuthorizerUrl: https://code-admin-api.example.com/internal/v1/object-storage/authorize-admin
  maximumPresignTtlSeconds: 60
  cohortTenants: ["*"]
  deleteEnabled: true
  deleteCohortTenants: [local-tenant]
workloadIdentity:
  issuer: https://cluster.example.com
  clusterRef: code-cloud
  audience: tikti-workload-exchange
  jwksUrl: https://cluster.example.com/jwks
`
	if _, err := LoadConfig(writeTempConfig(t, configuration)); err != nil {
		t.Fatalf("explicit all-tenant cohort: %v", err)
	}
	mixed := strings.Replace(configuration, `cohortTenants: ["*"]`, `cohortTenants: ["*", storifly]`, 1)
	if _, err := LoadConfig(writeTempConfig(t, mixed)); err == nil {
		t.Fatal("mixed wildcard and named browser cohorts were accepted")
	}
}
