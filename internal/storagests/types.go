package storagests

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"time"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	AWSQueryVersion          = "2011-06-15"
	AWSQueryAction           = "AssumeRoleWithWebIdentity"
	AWSQueryXMLNamespace     = "https://sts.amazonaws.com/doc/2011-06-15/"
	AuthorizerAudience       = "code-admin-object-storage-authorizer"
	MinIOAudience            = "minio-sts"
	ObjectStorageVersion     = "object-storage.v1"
	ReadOnlyAccess           = "ReadOnly"
	ReadWriteAccess          = "ReadWrite"
	defaultCredentialTTL     = 900
	maxRequestBodyBytes      = 32 << 10
	maxWebIdentityTokenBytes = 16 << 10
)

var (
	ErrDependencyUnavailable     = errors.New("storage STS dependency unavailable")
	ErrInvalidDependencyResponse = errors.New("storage STS dependency response invalid")
)

// Code is the closed public AWS-style error vocabulary returned by the broker.
type Code string

const (
	CodeInvalidParameterValue Code = "InvalidParameterValue"
	CodeInvalidIdentityToken  Code = "InvalidIdentityToken"
	CodeAccessDenied          Code = "AccessDenied"
	CodeIDPCommunicationError Code = "IDPCommunicationError"
	CodeServiceUnavailable    Code = "ServiceUnavailable"
	CodeInternalFailure       Code = "InternalFailure"
	CodeThrottling            Code = "Throttling"
)

// Error contains only stable public information. Dependency text and input
// values must never be copied into it.
type Error struct {
	Code       Code
	HTTPStatus int
	Reason     string
	Message    string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return string(e.Code)
}

func invalidParameterError() *Error {
	return &Error{
		Code: CodeInvalidParameterValue, HTTPStatus: http.StatusBadRequest,
		Reason: "invalid_request", Message: "The request parameters are invalid.",
	}
}

// Role is the parsed lookup key from the synthetic ARN. It carries no grant.
type Role struct {
	AccountID   string
	TenantID    string
	Namespace   string
	BindingName string
}

// Request is the strict, bounded public query contract.
type Request struct {
	RoleARN          string
	Role             Role
	RoleSessionName  string
	WebIdentityToken string
	DurationSeconds  int
}

// AuthorizationRequest is the exact secret-free request sent to the central
// current-state authorizer.
type AuthorizationRequest struct {
	SchemaVersion            string `json:"schemaVersion"`
	RoleARN                  string `json:"roleArn"`
	Issuer                   string `json:"issuer"`
	ClusterRef               string `json:"clusterRef"`
	Namespace                string `json:"namespace"`
	ServiceAccount           string `json:"serviceAccount"`
	Subject                  string `json:"subject"`
	TokenSHA256              string `json:"tokenSha256"`
	RequestedDurationSeconds int    `json:"requestedDurationSeconds"`
	RequestID                string `json:"requestId"`
}

type AuthorizationBinding struct {
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
	Policy     string `json:"policy"`
}

type AuthorizationBucket struct {
	UID                string `json:"uid"`
	Generation         int64  `json:"generation"`
	ObservedGeneration int64  `json:"observedGeneration"`
	ProviderBucketName string `json:"providerBucketName"`
	Endpoint           string `json:"endpoint"`
	STSEndpoint        string `json:"stsEndpoint"`
	Region             string `json:"region"`
}

type AuthorizationInstallation struct {
	ID     string `json:"id"`
	Region string `json:"region"`
}

type AuthorizationDecision struct {
	SchemaVersion               string                     `json:"schemaVersion"`
	Allowed                     bool                       `json:"allowed"`
	Reason                      string                     `json:"reason"`
	Binding                     *AuthorizationBinding      `json:"binding,omitempty"`
	Bucket                      *AuthorizationBucket       `json:"bucket,omitempty"`
	Installation                *AuthorizationInstallation `json:"installation,omitempty"`
	MaximumCredentialTTLSeconds int                        `json:"maximumCredentialTtlSeconds,omitempty"`
}

// Approval is assembled exclusively from verified identity and the current
// central allow decision. Public request fields cannot override its claims.
type Approval struct {
	Identity domain.WorkloadSubject
	Role     Role
	Decision AuthorizationDecision
}

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

type Result struct {
	Credentials    Credentials
	AssumedRoleARN string
	AssumedRoleID  string
	Audience       string
	Provider       string
	Subject        string
}

type ProjectedTokenVerifier interface {
	Verify(context.Context, string) (domain.WorkloadSubject, error)
}

type AssertionSigner interface {
	SignServiceAssertion(time.Time) (string, error)
	SignMinIOAssertion(time.Time, Approval) (string, error)
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest, string) (AuthorizationDecision, error)
}

type CredentialIssuer interface {
	Exchange(context.Context, string, int) (Credentials, error)
}

type Broker interface {
	Exchange(context.Context, Request, string) (Result, *Error)
}

type assumeRoleResponseXML struct {
	XMLName  xml.Name            `xml:"AssumeRoleWithWebIdentityResponse"`
	XMLNS    string              `xml:"xmlns,attr"`
	Result   assumeRoleResultXML `xml:"AssumeRoleWithWebIdentityResult"`
	Metadata responseMetadataXML `xml:"ResponseMetadata"`
}

type assumeRoleResultXML struct {
	Audience                    string             `xml:"Audience"`
	AssumedRoleUser             assumedRoleUserXML `xml:"AssumedRoleUser"`
	Credentials                 credentialsXML     `xml:"Credentials"`
	PackedPolicySize            int                `xml:"PackedPolicySize"`
	Provider                    string             `xml:"Provider"`
	SubjectFromWebIdentityToken string             `xml:"SubjectFromWebIdentityToken"`
}

type assumedRoleUserXML struct {
	ARN string `xml:"Arn"`
	ID  string `xml:"AssumedRoleId"`
}

type credentialsXML struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type responseMetadataXML struct {
	RequestID string `xml:"RequestId"`
}

type errorResponseXML struct {
	XMLName   xml.Name       `xml:"ErrorResponse"`
	XMLNS     string         `xml:"xmlns,attr"`
	Error     errorDetailXML `xml:"Error"`
	RequestID string         `xml:"RequestId"`
}

type errorDetailXML struct {
	Type    string `xml:"Type"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}
