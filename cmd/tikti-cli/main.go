package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

type configFile struct {
	CurrentProfile string                   `json:"currentProfile" yaml:"currentProfile"`
	Profiles       map[string]*profileEntry `json:"profiles" yaml:"profiles"`
}

type profileEntry struct {
	BaseURL     string `json:"baseUrl" yaml:"baseUrl"`
	ApiKey      string `json:"apiKey" yaml:"apiKey"`
	TenantId    string `json:"tenantId" yaml:"tenantId"`
	IdToken     string `json:"idToken" yaml:"idToken"`
	AccessToken string `json:"accessToken" yaml:"accessToken"`
	WorkerToken string `json:"workerToken" yaml:"workerToken"`
}

type cliError struct {
	msg  string
	exit int
}

func (e *cliError) Error() string {
	return e.msg
}

func main() {
	var (
		profileName string
		outputJSON  bool
		outputMode  string
	)

	root := &cobra.Command{
		Use:   "tikti",
		Short: "Tikti CLI",
	}

	root.PersistentFlags().StringVar(&profileName, "profile", "", "Profile name")
	root.PersistentFlags().BoolVar(&outputJSON, "output-json", false, "JSON output (deprecated)")
	root.PersistentFlags().StringVar(&outputMode, "output", "pretty", "Output format: pretty|json")
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if outputJSON {
			outputMode = "json"
		}
		switch outputMode {
		case "pretty":
			outputJSON = false
		case "json":
			outputJSON = true
		default:
			return &cliError{msg: "invalid output format", exit: 1}
		}
		return nil
	}

	root.AddCommand(initCmd(&profileName, &outputJSON))
	root.AddCommand(authCmd(&profileName, &outputJSON))
	root.AddCommand(tokenCmd(&profileName, &outputJSON))
	root.AddCommand(configCmd(&profileName, &outputJSON))
	root.AddCommand(apiKeyCmd(&profileName, &outputJSON))
	root.AddCommand(userCmd(&profileName, &outputJSON))
	root.AddCommand(tenantCmd(&profileName, &outputJSON))
	root.AddCommand(membershipCmd(&profileName, &outputJSON))
	root.AddCommand(roleCmd(&profileName, &outputJSON))
	root.AddCommand(clientCmd(&profileName, &outputJSON))
	root.AddCommand(revokeCmd(&profileName, &outputJSON))
	root.AddCommand(jwksCmd(&profileName, &outputJSON))
	root.AddCommand(samlCmd(&profileName, &outputJSON))

	if err := root.Execute(); err != nil {
		var ce *cliError
		if errors.As(err, &ce) {
			fmt.Fprintln(os.Stderr, ce.msg)
			os.Exit(ce.exit)
		}
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func initCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var (
		baseURL  string
		apiKey   string
		tenant   string
		noPrompt bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize CLI configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, path, err := loadConfig()
			if err != nil {
				return err
			}
			profile := resolveProfile(*profileName, cfg)
			entry := cfg.Profiles[profile]
			if entry == nil {
				entry = &profileEntry{}
			}
			if baseURL == "" && !noPrompt {
				baseURL = prompt("Base URL", entry.BaseURL, false)
			}
			if apiKey == "" && !noPrompt {
				apiKey = prompt("API Key", entry.ApiKey, false)
			}
			if tenant == "" && !noPrompt {
				tenant = prompt("Tenant ID", entry.TenantId, false)
			}
			if baseURL != "" {
				entry.BaseURL = strings.TrimRight(baseURL, "/")
			}
			if apiKey != "" {
				entry.ApiKey = apiKey
			}
			if tenant != "" {
				entry.TenantId = tenant
			}
			cfg.Profiles[profile] = entry
			cfg.CurrentProfile = profile
			if err := saveConfig(path, cfg); err != nil {
				return err
			}
			return printResult(*outputJSON, map[string]any{"profile": profile, "configPath": path})
		},
	}
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Tikti base URL")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "API key")
	cmd.Flags().StringVar(&tenant, "tenant", "", "Default tenant id")
	cmd.Flags().BoolVar(&noPrompt, "no-prompt", false, "Disable prompts")
	return cmd
}

func authCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var email, password string
	cmd := &cobra.Command{Use: "auth", Short: "Auth commands"}
	login := &cobra.Command{
		Use:   "login",
		Short: "Login with email and password",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, path, err := loadConfig()
			if err != nil {
				return err
			}
			prof := cfg.Profiles[resolveProfile(*profileName, cfg)]
			if prof == nil {
				return errors.New("profile not initialized")
			}
			if email == "" {
				email = prompt("Email", "", false)
			}
			if password == "" {
				password = prompt("Password", "", true)
			}
			body := map[string]any{"email": email, "password": password, "returnSecureToken": true}
			resp, err := doJSON(http.MethodPost, prof.BaseURL+"/v1/accounts/signInWithPassword?key="+prof.ApiKey, "", body)
			if err != nil {
				return err
			}
			token, _ := resp["idToken"].(string)
			if token == "" {
				return errors.New("missing idToken in response")
			}
			prof.IdToken = token
			cfg.Profiles[cfg.CurrentProfile] = prof
			if err := saveConfig(path, cfg); err != nil {
				return err
			}
			return printResult(*outputJSON, map[string]any{"email": email, "token": "stored"})
		},
	}
	login.Flags().StringVar(&email, "email", "", "User email")
	login.Flags().StringVar(&password, "password", "", "User password")
	cmd.AddCommand(login)
	logout := &cobra.Command{
		Use:   "logout",
		Short: "Clear stored tokens for the active profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, path, err := loadConfig()
			if err != nil {
				return err
			}
			profile := resolveProfile(*profileName, cfg)
			entry := cfg.Profiles[profile]
			if entry == nil {
				return errors.New("profile not initialized")
			}
			entry.IdToken = ""
			entry.AccessToken = ""
			entry.WorkerToken = ""
			cfg.Profiles[profile] = entry
			if err := saveConfig(path, cfg); err != nil {
				return err
			}
			return printResult(*outputJSON, map[string]any{"profile": profile, "status": "logged_out"})
		},
	}
	cmd.AddCommand(logout)
	return cmd
}

func tokenCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var (
		audience   string
		scopes     string
		eventTypes string
		ttl        int
		subject    string
		tenant     string
	)
	cmd := &cobra.Command{Use: "token", Short: "Token operations"}
	exchange := &cobra.Command{
		Use:   "exchange",
		Short: "Exchange idToken for access token",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			prof := cfg.Profiles[resolveProfile(*profileName, cfg)]
			if prof == nil {
				return errors.New("profile not initialized")
			}
			if audience == "" {
				return errors.New("audience required")
			}
			if tenant == "" {
				tenant = prof.TenantId
			}
			req := map[string]any{
				"idToken":    prof.IdToken,
				"audience":   audience,
				"scopes":     splitCSV(scopes),
				"eventTypes": splitCSV(eventTypes),
				"ttlSeconds": ttl,
				"subject":    subject,
				"tenantId":   tenant,
			}
			resp, err := doJSON(http.MethodPost, prof.BaseURL+"/v1/accounts/token/exchange?key="+prof.ApiKey, "", req)
			if err != nil {
				return err
			}
			token, _ := resp["accessToken"].(string)
			if token == "" {
				return errors.New("missing accessToken")
			}
			if audience == "codeq-worker" {
				prof.WorkerToken = token
			} else {
				prof.AccessToken = token
			}
			cfg.Profiles[cfg.CurrentProfile] = prof
			_, path, _ := loadConfig()
			_ = saveConfig(path, cfg)
			return printResult(*outputJSON, resp)
		},
	}
	exchange.Flags().StringVar(&audience, "audience", "", "Audience")
	exchange.Flags().StringVar(&scopes, "scopes", "", "Comma-separated scopes")
	exchange.Flags().StringVar(&eventTypes, "event-types", "", "Comma-separated event types")
	exchange.Flags().IntVar(&ttl, "ttl", 3600, "TTL in seconds")
	exchange.Flags().StringVar(&subject, "subject", "", "Subject")
	exchange.Flags().StringVar(&tenant, "tenant", "", "Tenant id")
	cmd.AddCommand(exchange)
	show := &cobra.Command{
		Use:   "show",
		Short: "Show stored token",
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, _ := cmd.Flags().GetString("type")
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			var token string
			switch kind {
			case "id":
				token = prof.IdToken
			case "access":
				token = prof.AccessToken
			case "worker":
				token = prof.WorkerToken
			default:
				return errors.New("type must be id, access, or worker")
			}
			return printResult(*outputJSON, map[string]any{"type": kind, "token": token})
		},
	}
	show.Flags().String("type", "access", "Token type: id|access|worker")
	cmd.AddCommand(show)
	return cmd
}

func userCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var email, password, role string
	cmd := &cobra.Command{Use: "user", Short: "User administration"}
	get := &cobra.Command{
		Use:   "get",
		Short: "Get current user info from idToken",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			token, _ := cmd.Flags().GetString("id-token")
			if token == "" {
				token = prof.IdToken
			}
			if token == "" {
				return errors.New("idToken missing")
			}
			body := map[string]any{"idToken": token}
			resp, err := doJSON(http.MethodPost, prof.BaseURL+"/v1/accounts/lookup?key="+prof.ApiKey, "", body)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	get.Flags().String("id-token", "", "Override idToken")
	cmd.AddCommand(get)
	create := &cobra.Command{
		Use:   "create",
		Short: "Create user",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			if email == "" {
				email = prompt("Email", "", false)
			}
			if password == "" {
				password = prompt("Password", "", true)
			}
			body := map[string]any{"email": email, "password": password, "role": role}
			resp, err := doJSON(http.MethodPost, prof.BaseURL+"/v1/accounts/signUp", prof.IdToken, body)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	create.Flags().StringVar(&email, "email", "", "User email")
	create.Flags().StringVar(&password, "password", "", "User password")
	create.Flags().StringVar(&role, "role", "COMPANY_EMPLOYEE", "User role")
	cmd.AddCommand(create)

	del := &cobra.Command{
		Use:   "delete",
		Short: "Delete the current user (idToken owner)",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			confirm, _ := cmd.Flags().GetBool("confirm")
			if !confirm {
				return errors.New("delete requires --confirm")
			}
			token, _ := cmd.Flags().GetString("id-token")
			if token == "" {
				token = prof.IdToken
			}
			if token == "" {
				return errors.New("idToken missing")
			}
			body := map[string]any{"idToken": token}
			resp, err := doJSON(http.MethodPost, prof.BaseURL+"/v1/accounts/delete?key="+prof.ApiKey, "", body)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	del.Flags().Bool("confirm", false, "Confirm deletion")
	del.Flags().String("id-token", "", "Override idToken")
	cmd.AddCommand(del)

	suspend := &cobra.Command{
		Use:   "suspend",
		Short: "Set user status to SUSPENDED",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			if email == "" {
				email = prompt("Email", "", false)
			}
			body := map[string]any{"email": email, "status": "SUSPENDED"}
			resp, err := doJSON(http.MethodPost, prof.BaseURL+"/v1/accounts/status?key="+prof.ApiKey, prof.IdToken, body)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	activate := &cobra.Command{
		Use:   "activate",
		Short: "Set user status to ACTIVE",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			if email == "" {
				email = prompt("Email", "", false)
			}
			body := map[string]any{"email": email, "status": "ACTIVE"}
			resp, err := doJSON(http.MethodPost, prof.BaseURL+"/v1/accounts/status?key="+prof.ApiKey, prof.IdToken, body)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	suspend.Flags().StringVar(&email, "email", "", "User email")
	activate.Flags().StringVar(&email, "email", "", "User email")
	cmd.AddCommand(suspend)
	cmd.AddCommand(activate)
	return cmd
}

func tenantCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var name, slug string
	cmd := &cobra.Command{Use: "tenant", Short: "Tenant operations"}
	create := &cobra.Command{
		Use:   "create",
		Short: "Create tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			body := map[string]any{"name": name, "slug": slug}
			resp, err := doJSON(http.MethodPost, prof.BaseURL+"/v1/tenants?key="+prof.ApiKey, prof.IdToken, body)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	create.Flags().StringVar(&name, "name", "", "Tenant name")
	create.Flags().StringVar(&slug, "slug", "", "Tenant slug")
	cmd.AddCommand(create)
	get := &cobra.Command{
		Use:   "get",
		Short: "Get tenant details",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			id, _ := cmd.Flags().GetString("tenant")
			if id == "" {
				id = prof.TenantId
			}
			if id == "" {
				return errors.New("tenant id required")
			}
			resp, err := doJSON(http.MethodGet, prof.BaseURL+"/v1/tenants/id/"+id+"?key="+prof.ApiKey, prof.IdToken, nil)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	get.Flags().String("tenant", "", "Tenant id")
	cmd.AddCommand(get)
	return cmd
}

func membershipCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var tenant, email, roles string
	cmd := &cobra.Command{Use: "membership", Short: "Membership operations"}
	add := &cobra.Command{
		Use:   "add",
		Short: "Add user to tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			if tenant == "" {
				tenant = prof.TenantId
			}
			body := map[string]any{"email": email, "roles": splitCSV(roles)}
			resp, err := doJSON(http.MethodPost, prof.BaseURL+"/v1/tenants/"+tenant+"/users?key="+prof.ApiKey, prof.IdToken, body)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	add.Flags().StringVar(&tenant, "tenant", "", "Tenant id")
	add.Flags().StringVar(&email, "email", "", "User email")
	add.Flags().StringVar(&roles, "roles", "", "Comma-separated roles")
	cmd.AddCommand(add)
	remove := &cobra.Command{
		Use:   "remove",
		Short: "Remove user from tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			if tenant == "" {
				tenant = prof.TenantId
			}
			if tenant == "" {
				return errors.New("tenant id required")
			}
			if email == "" {
				email = prompt("Email", "", false)
			}
			body := map[string]any{"email": email}
			resp, err := doJSON(http.MethodPost, prof.BaseURL+"/v1/tenants/"+tenant+"/users/remove?key="+prof.ApiKey, prof.IdToken, body)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	remove.Flags().StringVar(&tenant, "tenant", "", "Tenant id")
	remove.Flags().StringVar(&email, "email", "", "User email")
	cmd.AddCommand(remove)
	return cmd
}

func roleCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var tenant, name, perms string
	cmd := &cobra.Command{Use: "role", Short: "Role operations"}
	create := &cobra.Command{
		Use:   "create",
		Short: "Create role",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			if tenant == "" {
				tenant = prof.TenantId
			}
			body := map[string]any{"name": name, "permissions": splitCSV(perms)}
			resp, err := doJSON(http.MethodPost, prof.BaseURL+"/v1/tenants/"+tenant+"/roles?key="+prof.ApiKey, prof.IdToken, body)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	create.Flags().StringVar(&tenant, "tenant", "", "Tenant id")
	create.Flags().StringVar(&name, "name", "", "Role name")
	create.Flags().StringVar(&perms, "permissions", "", "Comma-separated permissions")
	cmd.AddCommand(create)
	list := &cobra.Command{
		Use:   "list",
		Short: "List roles for a tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			if tenant == "" {
				tenant = prof.TenantId
			}
			if tenant == "" {
				return errors.New("tenant id required")
			}
			resp, err := doJSON(http.MethodGet, prof.BaseURL+"/v1/tenants/"+tenant+"/roles?key="+prof.ApiKey, prof.IdToken, nil)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	list.Flags().StringVar(&tenant, "tenant", "", "Tenant id")
	cmd.AddCommand(list)
	return cmd
}

func clientCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var tenant, clientID, ctype, grants, scopes string
	cmd := &cobra.Command{Use: "client", Short: "Client operations"}
	create := &cobra.Command{
		Use:   "create",
		Short: "Create client",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			if tenant == "" {
				tenant = prof.TenantId
			}
			body := map[string]any{
				"clientId":          clientID,
				"type":              ctype,
				"allowedGrantTypes": splitCSV(grants),
				"defaultScopes":     splitCSV(scopes),
			}
			resp, err := doJSON(http.MethodPost, prof.BaseURL+"/v1/tenants/"+tenant+"/clients?key="+prof.ApiKey, prof.IdToken, body)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	create.Flags().StringVar(&tenant, "tenant", "", "Tenant id")
	create.Flags().StringVar(&clientID, "client-id", "", "Client id")
	create.Flags().StringVar(&ctype, "type", "SERVICE", "Client type")
	create.Flags().StringVar(&grants, "grant", "token_exchange", "Comma-separated grants")
	create.Flags().StringVar(&scopes, "scopes", "", "Comma-separated scopes")
	cmd.AddCommand(create)
	list := &cobra.Command{
		Use:   "list",
		Short: "List clients for a tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			if tenant == "" {
				tenant = prof.TenantId
			}
			if tenant == "" {
				return errors.New("tenant id required")
			}
			resp, err := doJSON(http.MethodGet, prof.BaseURL+"/v1/tenants/"+tenant+"/clients?key="+prof.ApiKey, prof.IdToken, nil)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	list.Flags().StringVar(&tenant, "tenant", "", "Tenant id")
	cmd.AddCommand(list)
	get := &cobra.Command{
		Use:   "get",
		Short: "Get a client by id",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			if tenant == "" {
				tenant = prof.TenantId
			}
			if tenant == "" || clientID == "" {
				return errors.New("tenant and client id required")
			}
			resp, err := doJSON(http.MethodGet, prof.BaseURL+"/v1/tenants/"+tenant+"/clients/"+clientID+"?key="+prof.ApiKey, prof.IdToken, nil)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	get.Flags().StringVar(&tenant, "tenant", "", "Tenant id")
	get.Flags().StringVar(&clientID, "client-id", "", "Client id")
	cmd.AddCommand(get)
	return cmd
}

func revokeCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var email, tenant, scope string
	cmd := &cobra.Command{Use: "revoke", Short: "Revocation operations"}
	tokens := &cobra.Command{
		Use:   "tokens",
		Short: "Revoke access tokens for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			if email == "" {
				email = prompt("Email", "", false)
			}
			body := map[string]any{"email": email}
			if tenant != "" {
				body["tenantId"] = tenant
			}
			if scope != "" {
				body["scope"] = scope
			}
			resp, err := doJSON(http.MethodPost, prof.BaseURL+"/v1/accounts/revoke?key="+prof.ApiKey, prof.IdToken, body)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	tokens.Flags().StringVar(&email, "email", "", "User email")
	tokens.Flags().StringVar(&tenant, "tenant", "", "Tenant id")
	tokens.Flags().StringVar(&scope, "scope", "", "Scope to revoke")
	cmd.AddCommand(tokens)
	return cmd
}

func jwksCmd(profileName *string, outputJSON *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jwks",
		Short: "Fetch JWKS",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			resp, err := doJSON(http.MethodGet, prof.BaseURL+"/v1/.well-known/jwks.json", "", nil)
			if err != nil {
				return err
			}
			return printResult(*outputJSON, resp)
		},
	}
	return cmd
}

func configCmd(profileName *string, outputJSON *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Local configuration"}
	show := &cobra.Command{
		Use:   "show",
		Short: "Show active profile configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			profile := resolveProfile(*profileName, cfg)
			entry := cfg.Profiles[profile]
			if entry == nil {
				return errors.New("profile not initialized")
			}
			out := map[string]any{
				"profile":  profile,
				"baseUrl":  entry.BaseURL,
				"apiKey":   entry.ApiKey,
				"tenantId": entry.TenantId,
			}
			return printResult(*outputJSON, out)
		},
	}
	set := &cobra.Command{
		Use:   "set",
		Short: "Update base URL, API key, or default tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, path, err := loadConfig()
			if err != nil {
				return err
			}
			profile := resolveProfile(*profileName, cfg)
			entry := cfg.Profiles[profile]
			if entry == nil {
				entry = &profileEntry{}
			}
			baseURL, _ := cmd.Flags().GetString("base-url")
			apiKey, _ := cmd.Flags().GetString("api-key")
			tenant, _ := cmd.Flags().GetString("tenant")
			if baseURL != "" {
				entry.BaseURL = strings.TrimRight(baseURL, "/")
			}
			if apiKey != "" {
				entry.ApiKey = apiKey
			}
			if tenant != "" {
				entry.TenantId = tenant
			}
			cfg.Profiles[profile] = entry
			cfg.CurrentProfile = profile
			if err := saveConfig(path, cfg); err != nil {
				return err
			}
			return printResult(*outputJSON, map[string]any{"profile": profile, "status": "updated"})
		},
	}
	set.Flags().String("base-url", "", "Tikti base URL")
	set.Flags().String("api-key", "", "API key")
	set.Flags().String("tenant", "", "Default tenant id")
	cmd.AddCommand(show)
	cmd.AddCommand(set)
	return cmd
}

func apiKeyCmd(profileName *string, outputJSON *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "apikey", Short: "API key helpers"}
	set := &cobra.Command{
		Use:   "set",
		Short: "Store API key in the active profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, path, err := loadConfig()
			if err != nil {
				return err
			}
			profile := resolveProfile(*profileName, cfg)
			entry := cfg.Profiles[profile]
			if entry == nil {
				entry = &profileEntry{}
			}
			val, _ := cmd.Flags().GetString("value")
			if val == "" {
				val = prompt("API Key", entry.ApiKey, false)
			}
			entry.ApiKey = val
			cfg.Profiles[profile] = entry
			cfg.CurrentProfile = profile
			if err := saveConfig(path, cfg); err != nil {
				return err
			}
			return printResult(*outputJSON, map[string]any{"profile": profile, "status": "updated"})
		},
	}
	set.Flags().String("value", "", "API key value")
	cmd.AddCommand(set)
	return cmd
}

func loadProfile(name string) (*profileEntry, error) {
	cfg, _, err := loadConfig()
	if err != nil {
		return nil, err
	}
	profName := resolveProfile(name, cfg)
	prof := cfg.Profiles[profName]
	if prof == nil {
		return nil, &cliError{msg: "profile not initialized", exit: 3}
	}
	return prof, nil
}

func resolveProfile(name string, cfg *configFile) string {
	if name != "" {
		return name
	}
	if cfg.CurrentProfile != "" {
		return cfg.CurrentProfile
	}
	return "default"
}

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".tikti", "config.yaml")
}

func loadConfig() (*configFile, string, error) {
	path := configPath()
	cfg := &configFile{Profiles: map[string]*profileEntry{}}
	if b, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(b, cfg); err != nil {
			return nil, path, &cliError{msg: err.Error(), exit: 3}
		}
	} else if !os.IsNotExist(err) {
		return nil, path, &cliError{msg: err.Error(), exit: 3}
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]*profileEntry{}
	}
	return cfg, path, nil
}

func saveConfig(path string, cfg *configFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	return nil
}

func doJSON(method string, url string, token string, body any) (map[string]any, error) {
	var buf io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		return nil, err
	}
	if token != "" {
		if strings.HasPrefix(strings.ToLower(token), "bearer ") {
			req.Header.Set("Authorization", token)
		} else {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		exit := 1
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			exit = 2
		}
		return nil, &cliError{msg: fmt.Sprintf("error (%d): %s", resp.StatusCode, strings.TrimSpace(string(b))), exit: exit}
	}
	if len(b) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func prompt(label string, def string, secret bool) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	if secret {
		b, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		val := strings.TrimSpace(string(b))
		if val == "" {
			return def
		}
		return val
	}
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return def
	}
	return input
}

func printResult(jsonOut bool, v any) error {
	if jsonOut {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	switch t := v.(type) {
	case map[string]any:
		b, _ := json.MarshalIndent(t, "", "  ")
		fmt.Println(string(b))
	default:
		fmt.Printf("%v\n", v)
	}
	return nil
}
