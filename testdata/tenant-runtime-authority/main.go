// The cross-repository contract fixture is deliberately under testdata, absent
// from production binaries. Control is a bounded local stdin stream, not HTTP.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/osvaldoandrade/tikti/internal/app"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/testredis"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "tenant runtime fixture failed")
		os.Exit(1)
	}
}

func run() error {
	gin.SetMode(gin.TestMode)
	gin.DefaultWriter = io.Discard
	gin.DefaultErrorWriter = io.Discard
	log.SetOutput(io.Discard)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 16384)
	var initial struct {
		APIKey  string `json:"apiKey"`
		Enabled bool   `json:"enabled"`
	}
	if !scanner.Scan() || decode(scanner.Bytes(), &initial) != nil {
		return errors.New("invalid fixture setup")
	}
	redisServer, err := testredis.Start()
	if err != nil {
		return err
	}
	defer redisServer.Close()
	// Isolate this test process from operator Redis environment overrides.
	for _, key := range []string{"REDIS_URL", "REDIS_PASSWORD", "REDIS_HOST", "REDIS_PORT", "REDIS_DB"} {
		if err := os.Unsetenv(key); err != nil {
			return errors.New("isolate fixture environment")
		}
	}
	application, err := app.NewApplication(&config.Config{RedisURL: redisServer.URL, ApiKey: initial.APIKey, JwtSecret: strings.Repeat("j", 32), TenantRuntimeAuthorityV1: initial.Enabled})
	if err != nil {
		return errors.New("initialize actual application")
	}
	defer application.Redis.Close()
	application.Engine.Use(cors.New(cors.Config{AllowOrigins: []string{"https://console.example.com"}, AllowMethods: []string{"GET", "OPTIONS"}, AllowCredentials: true}))
	app.SetupMappings(application.Engine, application.Config, application.UserService, application.TenantSvc, application.RoleSvc, application.ClientSvc, application.WorkloadSvc, application.WorkloadAccountSvc, nil, nil)
	server := httptest.NewServer(application.Engine)
	defer server.Close()
	output := json.NewEncoder(os.Stdout)
	if err := output.Encode(struct {
		URL string `json:"url"`
	}{server.URL}); err != nil {
		return err
	}
	repo := repository.NewTenantRepo(application.Redis)
	for scanner.Scan() {
		var command struct {
			Action    string `json:"action"`
			TenantID  string `json:"tenantId"`
			State     string `json:"state"`
			CreatedAt string `json:"createdAt"`
			Raw       string `json:"raw"`
		}
		err := decode(scanner.Bytes(), &command)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err == nil {
			switch command.Action {
			case "seed":
				birth, parseErr := time.Parse(time.RFC3339Nano, command.CreatedAt)
				if parseErr != nil || birth.IsZero() || (command.State != "ACTIVE" && command.State != "DISABLED") {
					err = errors.New("invalid seed")
					break
				}
				err = repo.Create(ctx, &domain.Tenant{Id: command.TenantID, Slug: command.TenantID, Name: "Fixture tenant", Status: domain.TenantStatus(command.State), CreatedAt: birth})
			case "retire":
				err = repo.(interface {
					Retire(context.Context, string) error
				}).Retire(ctx, command.TenantID)
			case "raw":
				if len(command.Raw) > 8192 {
					err = errors.New("invalid raw size")
				} else {
					err = application.Redis.HSet(ctx, "tenants", command.TenantID, command.Raw).Err()
				}
			case "outage":
				redisServer.Close()
			default:
				err = errors.New("invalid action")
			}
		}
		cancel()
		if err != nil {
			err = output.Encode(struct {
				Error string `json:"error"`
			}{"FixtureCommandFailed"})
		} else {
			err = output.Encode(struct {
				OK bool `json:"ok"`
			}{true})
		}
		if err != nil {
			return err
		}
	}
	return scanner.Err()
}

func decode(raw []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid command")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("extra command data")
	}
	return nil
}
