package app

import (
	"time"

	"github.com/osvaldoandrade/tikti/internal/managedlogs"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

func newManagedLogsOption(cfg *config.Config, tenants services.CodeQTopicTenantReader) (services.WorkloadIdentityServiceOption, error) {
	p := cfg.WorkloadIdentity.ManagedLogs
	if !p.Enabled {
		return services.WithManagedLogs(services.ManagedLogsExchangeConfig{}, nil, nil), nil
	}
	client, err := managedlogs.NewClient(p.AuthorityURL, time.Duration(p.DependencyTimeoutSeconds)*time.Second)
	if err != nil {
		return nil, err
	}
	return services.WithManagedLogs(services.ManagedLogsExchangeConfig{Enabled: true, TTL: time.Duration(p.AccessTokenTTLSeconds) * time.Second, MaximumConcurrent: p.MaximumConcurrent, PerIdentityPerMinute: p.PerIdentityPerMinute}, client, tenants), nil
}
