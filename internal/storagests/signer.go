package storagests

import (
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/osvaldoandrade/tikti/internal/utils"
)

type SigningConfig struct {
	Issuer              string
	ServiceSubject      string
	KeyID               string
	PrivateKeyPEM       string
	ServiceAssertionTTL time.Duration
	CredentialTTL       time.Duration
	ReadOnlyPolicy      string
	ReadWritePolicy     string
}

type Signer struct {
	issuer, serviceSubject, keyID   string
	key                             *rsa.PrivateKey
	serviceTTL, credentialTTL       time.Duration
	readOnlyPolicy, readWritePolicy string
}

func NewSigner(cfg SigningConfig) (*Signer, error) {
	key, err := utils.ParseRSAPrivateKey(cfg.PrivateKeyPEM)
	if err != nil || key.N.BitLen() < 2048 || !validHTTPSIssuer(cfg.Issuer) ||
		strings.TrimSpace(cfg.ServiceSubject) != "tikti:object-storage-sts" ||
		strings.TrimSpace(cfg.KeyID) == "" || len(strings.TrimSpace(cfg.KeyID)) > 128 ||
		cfg.ServiceAssertionTTL <= 0 || cfg.ServiceAssertionTTL > time.Minute ||
		cfg.CredentialTTL != 15*time.Minute ||
		cfg.ReadOnlyPolicy != "code-admin-object-readonly-v1" || cfg.ReadWritePolicy != "code-admin-object-readwrite-v1" {
		return nil, fmt.Errorf("invalid storage STS signing configuration")
	}
	return &Signer{
		issuer: strings.TrimSuffix(strings.TrimSpace(cfg.Issuer), "/"), serviceSubject: strings.TrimSpace(cfg.ServiceSubject),
		keyID: strings.TrimSpace(cfg.KeyID), key: key, serviceTTL: cfg.ServiceAssertionTTL,
		credentialTTL: cfg.CredentialTTL, readOnlyPolicy: cfg.ReadOnlyPolicy, readWritePolicy: cfg.ReadWritePolicy,
	}, nil
}

func (s *Signer) SignServiceAssertion(now time.Time) (string, error) {
	if s == nil || s.key == nil {
		return "", fmt.Errorf("storage STS signer unavailable")
	}
	now = now.UTC().Truncate(time.Second)
	return s.sign(jwt.MapClaims{
		"iss": s.issuer, "aud": AuthorizerAudience, "sub": s.serviceSubject,
		"jti": uuid.NewString(), "iat": now.Unix(), "nbf": now.Add(-5 * time.Second).Unix(),
		"exp": now.Add(s.serviceTTL).Unix(),
	})
}

func (s *Signer) SignMinIOAssertion(now time.Time, approval Approval) (string, error) {
	if s == nil || s.key == nil || !validAllowDecision(approval.Decision) ||
		approval.Identity.Subject == "" || approval.Identity.Issuer == "" || approval.Identity.ClusterRef == "" ||
		approval.Identity.Namespace != approval.Role.Namespace || approval.Role.TenantID == "" {
		return "", fmt.Errorf("invalid storage STS approval")
	}
	policy := s.readOnlyPolicy
	if approval.Decision.Binding.Policy == ReadWriteAccess {
		policy = s.readWritePolicy
	} else if approval.Decision.Binding.Policy != ReadOnlyAccess {
		return "", fmt.Errorf("invalid storage STS policy")
	}
	now = now.UTC().Truncate(time.Second)
	return s.sign(jwt.MapClaims{
		"iss": s.issuer, "aud": MinIOAudience, "client_id": MinIOAudience,
		"sub": approval.Identity.Subject, "tid": approval.Role.TenantID,
		"cluster_ref": approval.Identity.ClusterRef, "namespace": approval.Identity.Namespace,
		"service_account": approval.Identity.ServiceAccount,
		"binding_uid":     approval.Decision.Binding.UID, "binding_generation": approval.Decision.Binding.Generation,
		"bucket_uid": approval.Decision.Bucket.UID, "bucket_generation": approval.Decision.Bucket.ObservedGeneration,
		"preferred_username": approval.Decision.Bucket.ProviderBucketName, "policy": policy,
		"jti": uuid.NewString(), "iat": now.Unix(), "nbf": now.Add(-5 * time.Second).Unix(),
		"exp": now.Add(s.credentialTTL).Unix(),
	})
}

// SignAdminMinIOAssertion creates the short-lived assertion used only inside
// Tikti to obtain credentials for one reviewed administrative operation. An
// object key and the Console access token are intentionally absent.
func (s *Signer) SignAdminMinIOAssertion(now time.Time, approval AdminApproval) (string, error) {
	if s == nil || s.key == nil || approval.ActorSubject == "" || approval.ActorSubject != strings.TrimSpace(approval.ActorSubject) ||
		!validDNSLabel(approval.TenantID) || !validAdminAuthorizationDecision(approval.Decision, approval.Operation) {
		return "", fmt.Errorf("invalid administrative storage approval")
	}
	policy := s.readOnlyPolicy
	if approval.Operation == AdminOperationUpload {
		if approval.Decision.Policy != ReadWriteAccess {
			return "", fmt.Errorf("invalid administrative storage policy")
		}
		policy = s.readWritePolicy
	} else if (approval.Operation != AdminOperationList && approval.Operation != AdminOperationDownload) ||
		approval.Decision.Policy != ReadOnlyAccess {
		return "", fmt.Errorf("invalid administrative storage policy")
	}
	now = now.UTC().Truncate(time.Second)
	return s.sign(jwt.MapClaims{
		"iss": s.issuer, "aud": MinIOAudience, "client_id": MinIOAudience,
		"sub": approval.ActorSubject, "tid": approval.TenantID,
		"administrative_operation": string(approval.Operation),
		"bucket_uid":               approval.Decision.Bucket.UID,
		"bucket_generation":        approval.Decision.Bucket.ObservedGeneration,
		"preferred_username":       approval.Decision.Bucket.ProviderBucketName,
		"policy":                   policy,
		"jti":                      uuid.NewString(),
		"iat":                      now.Unix(),
		"nbf":                      now.Add(-5 * time.Second).Unix(),
		"exp":                      now.Add(s.credentialTTL).Unix(),
	})
}

func (s *Signer) sign(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID
	token.Header["typ"] = "JWT"
	return token.SignedString(s.key)
}
