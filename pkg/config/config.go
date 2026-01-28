package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// Config captures runtime parameters loaded from YAML or the environment.
type Config struct {
	Port            int    `yaml:"port"`
	RedisAddr       string `yaml:"redisAddr"`
	RedisHost       string `yaml:"redisHost"`
	RedisPort       int    `yaml:"redisPort"`
	RedisDB         int    `yaml:"redisDb"`
	RedisPassword   string `yaml:"redisPassword"`
	RedisURL        string `yaml:"redisUrl"`
	JwtSecret       string `yaml:"jwtSecret"`
	ApiKey          string `yaml:"apiKey"`
	IssuerBaseURL   string `yaml:"issuerBaseUrl"`
	DefaultAudience string `yaml:"defaultAudience"`
	JwksPrivateKey  string `yaml:"jwksPrivateKey"`
	JwksKeyID       string `yaml:"jwksKeyId"`
}

// LoadConfig reads a YAML file, expands environment variables, and returns Config defaults.
func LoadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	expanded := os.Expand(string(data), func(key string) string {
		if val, ok := os.LookupEnv(key); ok {
			return val
		}
		return "${" + key + "}"
	})
	data = []byte(expanded)

	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Port == 0 {
		c.Port = 8080
	}
	if c.RedisAddr == "" {
		c.RedisAddr = "localhost:6379"
	}
	if c.RedisHost == "" {
		c.RedisHost = "localhost"
	}
	if c.RedisPort == 0 {
		c.RedisPort = 6379
	}
	if c.RedisDB < 0 {
		c.RedisDB = 0
	}
	if c.JwtSecret == "" {
		c.JwtSecret = "supersecret"
	}
	if c.ApiKey == "" {
		log.Println("WARNING: No API key set.")
	}
	if v := os.Getenv("ISSUER_BASE_URL"); v != "" {
		c.IssuerBaseURL = v
	}
	if v := os.Getenv("DEFAULT_AUDIENCE"); v != "" {
		c.DefaultAudience = v
	}
	if v := os.Getenv("JWKS_PRIVATE_KEY"); v != "" {
		c.JwksPrivateKey = v
	}
	if v := os.Getenv("JWKS_KEY_ID"); v != "" {
		c.JwksKeyID = v
	}
	if c.IssuerBaseURL == "" {
		log.Println("WARNING: IssuerBaseURL not set. Using http://localhost:8080")
		c.IssuerBaseURL = "http://localhost:8080"
	}
	if c.DefaultAudience == "" {
		c.DefaultAudience = "tikti"
	}
	if c.JwksKeyID == "" {
		c.JwksKeyID = "tikti-local-1"
	}
	return &c, nil
}
