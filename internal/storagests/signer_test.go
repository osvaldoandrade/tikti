package storagests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestSignerSeparatesServiceAndMinIOAssertions(t *testing.T) {
	key, privatePEM := storageTestKey(t)
	signer, err := NewSigner(SigningConfig{
		Issuer: "https://tikti.example.com", ServiceSubject: "tikti:object-storage-sts", KeyID: "tikti-key-1",
		PrivateKeyPEM: privatePEM, ServiceAssertionTTL: time.Minute, CredentialTTL: 15 * time.Minute,
		ReadOnlyPolicy: "code-admin-object-readonly-v1", ReadWritePolicy: "code-admin-object-readwrite-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	serviceToken, err := signer.SignServiceAssertion(now)
	if err != nil {
		t.Fatal(err)
	}
	serviceClaims := parseStorageTestToken(t, key, serviceToken)
	if serviceClaims["iss"] != "https://tikti.example.com" || serviceClaims["aud"] != AuthorizerAudience ||
		serviceClaims["sub"] != "tikti:object-storage-sts" || serviceClaims["jti"] == "" ||
		int64(serviceClaims["exp"].(float64)-serviceClaims["iat"].(float64)) != 60 {
		t.Fatalf("service claims = %#v", serviceClaims)
	}
	for _, forbidden := range []string{"tid", "tenantId", "scope", "policy", "preferred_username", "bucket_uid"} {
		if _, found := serviceClaims[forbidden]; found {
			t.Fatalf("service assertion contains %q: %#v", forbidden, serviceClaims)
		}
	}

	approval := Approval{
		Identity: domain.WorkloadSubject{
			Subject: "system:serviceaccount:workload-payments:payments-api", Issuer: "https://cluster.example.com",
			ClusterRef: "code-cloud", Namespace: "workload-payments", ServiceAccount: "payments-api",
		},
		Role:     Role{TenantID: "payments", Namespace: "workload-payments", BindingName: "payments-api-invoices"},
		Decision: allowDecision(ReadWriteAccess),
	}
	minioToken, err := signer.SignMinIOAssertion(now, approval)
	if err != nil {
		t.Fatal(err)
	}
	minioClaims := parseStorageTestToken(t, key, minioToken)
	if minioClaims["aud"] != MinIOAudience || minioClaims["client_id"] != MinIOAudience ||
		minioClaims["sub"] != approval.Identity.Subject || minioClaims["tid"] != "payments" ||
		minioClaims["cluster_ref"] != "code-cloud" || minioClaims["namespace"] != "workload-payments" ||
		minioClaims["service_account"] != "payments-api" || minioClaims["binding_uid"] != "binding-uid" ||
		minioClaims["bucket_uid"] != "bucket-uid" || minioClaims["preferred_username"] != "cf-payments-invoices-47e89ff7e282" ||
		minioClaims["policy"] != "code-admin-object-readwrite-v1" ||
		int64(minioClaims["exp"].(float64)-minioClaims["iat"].(float64)) != 900 {
		t.Fatalf("MinIO claims = %#v", minioClaims)
	}
	if _, found := minioClaims["roleArn"]; found {
		t.Fatalf("MinIO assertion contains request role: %#v", minioClaims)
	}
}

func storageTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, string(encoded)
}

func parseStorageTestToken(t *testing.T, key *rsa.PrivateKey, tokenValue string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	parsed, err := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithoutClaimsValidation()).ParseWithClaims(
		tokenValue, claims, func(*jwt.Token) (interface{}, error) { return &key.PublicKey, nil },
	)
	if err != nil || parsed == nil || !parsed.Valid {
		t.Fatalf("parse assertion: %v", err)
	}
	return claims
}

func allowDecision(policy string) AuthorizationDecision {
	return AuthorizationDecision{
		SchemaVersion: ObjectStorageVersion, Allowed: true, Reason: "Allowed",
		Binding: &AuthorizationBinding{UID: "binding-uid", Generation: 4, Policy: policy},
		Bucket: &AuthorizationBucket{
			UID: "bucket-uid", Generation: 3, ObservedGeneration: 3,
			ProviderBucketName: "cf-payments-invoices-47e89ff7e282", Endpoint: "https://s3.example.com",
			STSEndpoint: "https://sts.example.com", Region: "us-central1",
		},
		Installation:                &AuthorizationInstallation{ID: "storage-code", Region: "us-central1"},
		MaximumCredentialTTLSeconds: 900,
	}
}
