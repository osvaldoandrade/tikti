package config

import (
	"strings"
	"testing"
)

func TestStorageSTSDefaultsOff(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StorageSTS.Enabled || cfg.StorageSTS.CredentialTTLSeconds != 900 ||
		cfg.StorageSTS.ServiceAssertionTTLSeconds != 60 || cfg.StorageSTS.MaximumConcurrent != 8 ||
		cfg.StorageSTS.DependencyTimeoutSeconds != 3 {
		t.Fatalf("storage STS defaults = %#v", cfg.StorageSTS)
	}
}

func TestStorageSTSValidatesIndependentExactBoundary(t *testing.T) {
	valid := `
issuerBaseUrl: https://tikti.example.com
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
workloadIdentity:
  issuer: https://cluster.example.com
  clusterRef: code-cloud
  audience: tikti-workload-exchange
  jwksUrl: https://cluster.example.com/jwks
`
	cfg, err := LoadConfig(writeTempConfig(t, valid))
	if err != nil || !cfg.StorageSTS.Enabled || cfg.WorkloadIdentity.ClusterRef != "code-cloud" {
		t.Fatalf("valid storage STS config=%#v error=%v", cfg, err)
	}

	for _, replacement := range []string{
		"syntheticAccountId: \"123\"",
		"authorizerUrl: https://evil.example.com/other",
		"minioStsEndpoint: http://evil.example.com/",
		"oidcJwksUrl: http://tikti.code-admin.svc:8080/v1/.well-known/jwks.json",
		"serviceSubject: other-service",
		"serviceSubject: \"\"",
		"credentialTtlSeconds: 0",
		"credentialTtlSeconds: 901",
		"serviceAssertionTtlSeconds: 61",
		"dependencyTimeoutSeconds: 11",
		"maximumConcurrent: 33",
		"readOnlyPolicy: arbitrary",
		"readWritePolicy: arbitrary",
		"audience: another-audience",
		"clusterRef: \"\"",
	} {
		body := strings.Replace(valid, replacementKey(replacement), replacement, 1)
		if _, loadErr := LoadConfig(writeTempConfig(t, body)); loadErr == nil {
			t.Fatalf("expected invalid config for %q", replacement)
		}
	}
}

func replacementKey(replacement string) string {
	key := strings.SplitN(strings.TrimSpace(replacement), ":", 2)[0]
	switch key {
	case "enabled":
		return "enabled: true"
	case "syntheticAccountId":
		return "syntheticAccountId: \"000000000000\""
	case "authorizerUrl":
		return "authorizerUrl: https://code-admin-api.example.com/internal/v1/object-storage:authorize"
	case "minioStsEndpoint":
		return "minioStsEndpoint: http://minio.code-admin.svc:9000/"
	case "oidcJwksUrl":
		return "oidcJwksUrl: http://tikti.code-admin.svc:8080/internal/v1/storage/jwks.json"
	case "serviceSubject":
		return "serviceSubject: tikti:object-storage-sts"
	case "credentialTtlSeconds":
		return "credentialTtlSeconds: 900"
	case "serviceAssertionTtlSeconds":
		return "serviceAssertionTtlSeconds: 60"
	case "dependencyTimeoutSeconds":
		return "dependencyTimeoutSeconds: 3"
	case "maximumConcurrent":
		return "maximumConcurrent: 8"
	case "readOnlyPolicy":
		return "readOnlyPolicy: code-admin-object-readonly-v1"
	case "readWritePolicy":
		return "readWritePolicy: code-admin-object-readwrite-v1"
	case "audience":
		return "audience: tikti-workload-exchange"
	case "clusterRef":
		return "clusterRef: code-cloud"
	default:
		return replacement
	}
}
