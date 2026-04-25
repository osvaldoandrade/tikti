package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/osvaldoandrade/tikti/internal/app"
	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

var configFile = flag.String("f", "config/tikti.yaml", "Path to the YAML config file")

func main() {
	flag.Parse()

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Wire SAML KeyHolder if SAML is enabled.
	if cfg.SAML.Enabled {
		if err := cfg.SAML.Validate(); err != nil {
			log.Fatalf("saml config invalid: %v", err)
		}
		kh := saml.NewKeyHolder(saml.KeyHolderConfig{
			WatchFile: cfg.SAML.SP.WatchFile,
		})
		if err := kh.LoadKey(cfg.SAML.SP.SigningKeyPath, cfg.SAML.SP.SigningCertPath); err != nil {
			log.Fatalf("saml: load SP key: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		kh.Start(ctx, cfg.SAML.SP.SigningKeyPath, cfg.SAML.SP.SigningCertPath)

		// Start background IdP metadata refresher if an interval is configured.
		if cfg.SAML.IdP.RefreshInterval > 0 {
			rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
			store := saml.NewRedisStore(rdb)
			m := saml.NewMetrics(prometheus.DefaultRegisterer)
			saml.NewRefresher(saml.RefresherConfig{
				Store:     store,
				Metrics:   m,
				Interval:  cfg.SAML.IdP.RefreshInterval,
				MaxJitter: saml.DefaultJitter,
			}).Start(ctx)
		}
	}

	application, err := app.NewApplication(cfg)
	if err != nil {
		log.Fatalf("failed to initialize application: %v", err)
	}

	application.Engine.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization", "X-API-Key"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	app.SetupMappings(
		application.Engine,
		cfg,
		application.UserService,
		application.TenantSvc,
		application.MemberSvc,
		application.RoleSvc,
		application.ClientSvc,
	)

	application.Engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	application.Run()
}
