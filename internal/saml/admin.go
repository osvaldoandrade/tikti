package saml

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	ErrAdminInvalidInput = errors.New("saml admin: invalid input")
	ErrAdminUnavailable  = errors.New("saml admin: unavailable")
)

var adminTenantPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

type IdPConfiguration struct {
	Configured                 bool                `json:"configured"`
	EntityID                   string              `json:"entityId,omitempty"`
	SSOURL                     string              `json:"ssoUrl,omitempty"`
	SLOURL                     string              `json:"sloUrl,omitempty"`
	MetadataURL                string              `json:"metadataUrl,omitempty"`
	NameIDFormat               string              `json:"nameIdFormat,omitempty"`
	AttributeMap               map[string][]string `json:"attributeMap,omitempty"`
	SigningCertificateCount    int                 `json:"signingCertificateCount,omitempty"`
	EncryptionCertificateCount int                 `json:"encryptionCertificateCount,omitempty"`
	LastFetched                time.Time           `json:"lastFetched,omitempty"`
	LoginURL                   string              `json:"loginUrl,omitempty"`
}

type PutIdPConfiguration struct {
	MetadataURL  string              `json:"metadataUrl"`
	MetadataXML  string              `json:"metadataXml"`
	AttributeMap map[string][]string `json:"attributeMap"`
}

type AdminService struct {
	store     Store
	fetcher   MetadataHTTPFetcher
	loginBase string
	metrics   *Metrics
}

func NewAdminService(store Store, fetcher MetadataHTTPFetcher, issuerBaseURL string, metrics *Metrics) *AdminService {
	return &AdminService{
		store:     store,
		fetcher:   fetcher,
		loginBase: strings.TrimRight(strings.TrimSpace(issuerBaseURL), "/"),
		metrics:   metrics,
	}
}

func (s *AdminService) Get(ctx context.Context, tenantID string) (IdPConfiguration, error) {
	if s == nil || s.store == nil {
		return IdPConfiguration{}, ErrAdminUnavailable
	}
	if !adminTenantPattern.MatchString(tenantID) {
		return IdPConfiguration{}, fmt.Errorf("%w: tenantId is invalid", ErrAdminInvalidInput)
	}
	record, err := s.store.GetIdP(ctx, tenantID)
	if errors.Is(err, ErrIdPNotFound) {
		return IdPConfiguration{Configured: false}, nil
	}
	if err != nil {
		return IdPConfiguration{}, fmt.Errorf("%w: read configuration", ErrAdminUnavailable)
	}
	return s.project(record), nil
}

func (s *AdminService) Put(ctx context.Context, tenantID string, input PutIdPConfiguration) (IdPConfiguration, error) {
	if s == nil || s.store == nil {
		return IdPConfiguration{}, ErrAdminUnavailable
	}
	if !adminTenantPattern.MatchString(tenantID) {
		return IdPConfiguration{}, fmt.Errorf("%w: tenantId is invalid", ErrAdminInvalidInput)
	}
	metadataURL := strings.TrimSpace(input.MetadataURL)
	metadataXML := strings.TrimSpace(input.MetadataXML)
	if (metadataURL == "") == (metadataXML == "") {
		return IdPConfiguration{}, fmt.Errorf("%w: provide exactly one of metadataUrl or metadataXml", ErrAdminInvalidInput)
	}
	if len(metadataURL) > 2048 {
		return IdPConfiguration{}, fmt.Errorf("%w: metadataUrl is too long", ErrAdminInvalidInput)
	}
	if len(metadataXML) > MaxMetadataBytes {
		return IdPConfiguration{}, fmt.Errorf("%w: metadataXml exceeds %d bytes", ErrAdminInvalidInput, MaxMetadataBytes)
	}
	attributeMap, err := validateAttributeMap(input.AttributeMap)
	if err != nil {
		return IdPConfiguration{}, err
	}

	var raw []byte
	if metadataURL != "" {
		raw, err = s.fetcher.Fetch(ctx, metadataURL)
		if err != nil {
			s.observeAdminChange("put", "failure")
			return IdPConfiguration{}, fmt.Errorf("%w: %v", ErrAdminInvalidInput, err)
		}
	} else {
		raw = []byte(metadataXML)
	}
	record, err := ParseIdPMetadata(raw)
	if err != nil {
		s.observeAdminChange("put", "failure")
		return IdPConfiguration{}, fmt.Errorf("%w: metadata validation failed: %v", ErrAdminInvalidInput, err)
	}
	record.TenantID = tenantID
	record.MetadataURL = metadataURL
	record.AttributeMap = attributeMap
	record.LastFetched = time.Now().UTC()
	if err := s.store.PutIdP(ctx, *record); err != nil {
		s.observeAdminChange("put", "failure")
		return IdPConfiguration{}, fmt.Errorf("%w: persist configuration", ErrAdminUnavailable)
	}
	s.observeAdminChange("put", "success")
	return s.project(*record), nil
}

func (s *AdminService) Delete(ctx context.Context, tenantID string) error {
	if s == nil || s.store == nil {
		return ErrAdminUnavailable
	}
	if !adminTenantPattern.MatchString(tenantID) {
		return fmt.Errorf("%w: tenantId is invalid", ErrAdminInvalidInput)
	}
	if err := s.store.DeleteIdP(ctx, tenantID); err != nil {
		s.observeAdminChange("delete", "failure")
		return fmt.Errorf("%w: delete configuration", ErrAdminUnavailable)
	}
	s.observeAdminChange("delete", "success")
	return nil
}

func (s *AdminService) project(record IdPRecord) IdPConfiguration {
	loginURL := ""
	if s.loginBase != "" {
		loginURL = s.loginBase + "/saml/login/" + url.PathEscape(record.TenantID)
	}
	return IdPConfiguration{
		Configured:                 true,
		EntityID:                   record.EntityID,
		SSOURL:                     record.SSOURL,
		SLOURL:                     record.SLOURL,
		MetadataURL:                record.MetadataURL,
		NameIDFormat:               record.NameIDFormat,
		AttributeMap:               cloneAttributeMap(record.AttributeMap),
		SigningCertificateCount:    len(record.SigningCerts),
		EncryptionCertificateCount: len(record.EncryptionCerts),
		LastFetched:                record.LastFetched,
		LoginURL:                   loginURL,
	}
}

func validateAttributeMap(input map[string][]string) (map[string][]string, error) {
	if input == nil {
		input = DefaultAttributeMap()
	}
	if len(input) == 0 || len(input) > 3 {
		return nil, fmt.Errorf("%w: attributeMap must contain email, name, or roles", ErrAdminInvalidInput)
	}
	out := make(map[string][]string, len(input))
	for field, aliases := range input {
		if field != "email" && field != "name" && field != "roles" {
			return nil, fmt.Errorf("%w: attributeMap field %q is not supported", ErrAdminInvalidInput, field)
		}
		if len(aliases) > 10 || field == "email" && len(aliases) == 0 {
			return nil, fmt.Errorf("%w: attributeMap.%s contains an invalid number of names", ErrAdminInvalidInput, field)
		}
		seen := make(map[string]struct{}, len(aliases))
		for _, alias := range aliases {
			alias = strings.TrimSpace(alias)
			if alias == "" || len(alias) > 512 {
				return nil, fmt.Errorf("%w: attributeMap.%s contains an invalid name", ErrAdminInvalidInput, field)
			}
			if alias == "tid" || alias == "tenant_id" || alias == "tenantId" {
				return nil, fmt.Errorf("%w: tenant attributes cannot be mapped", ErrAdminInvalidInput)
			}
			if _, exists := seen[alias]; exists {
				continue
			}
			seen[alias] = struct{}{}
			out[field] = append(out[field], alias)
		}
	}
	if len(out["email"]) == 0 {
		return nil, fmt.Errorf("%w: attributeMap.email is required", ErrAdminInvalidInput)
	}
	return out, nil
}

func DefaultAttributeMap() map[string][]string {
	return map[string][]string{
		"email": {"mail", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"},
		"name":  {"displayName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"},
		"roles": {"groups", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"},
	}
}

func cloneAttributeMap(input map[string][]string) map[string][]string {
	out := make(map[string][]string, len(input))
	for key, values := range input {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func (s *AdminService) observeAdminChange(operation, result string) {
	if s.metrics != nil && s.metrics.IdPAdminChanges != nil {
		s.metrics.IdPAdminChanges.WithLabelValues(operation, result).Inc()
	}
}
