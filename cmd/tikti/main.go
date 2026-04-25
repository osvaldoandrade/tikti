package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
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

	// Root context: cancelled when SIGTERM or SIGINT is received.
	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

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
		// Workers stop when rootCtx is cancelled (SIGTERM/SIGINT).
		kh.Start(rootCtx, cfg.SAML.SP.SigningKeyPath, cfg.SAML.SP.SigningCertPath)

		// Start background IdP metadata refresher if an interval is configured.
		if cfg.SAML.IdP.RefreshInterval > 0 {
			rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
			defer rdb.Close()
			store := saml.NewRedisStore(rdb)
			m := saml.NewMetrics(prometheus.DefaultRegisterer)
			spCert, err := saml.LoadCertFile(cfg.SAML.SP.SigningCertPath)
			if err != nil {
				log.Printf("saml: could not load SP signing cert for expiry monitoring: %v", err)
			}
			saml.NewRefresher(saml.RefresherConfig{
				Store:     store,
				Metrics:   m,
				Interval:  cfg.SAML.IdP.RefreshInterval,
				MaxJitter: saml.DefaultJitter,
				SPCertPEM: spCert,
			}).Start(rootCtx)
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

	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:    addr,
		Handler: application.Engine,
	}

	// Start HTTP server in background.
	go func() {
		log.Printf("Tikti running at %s\n", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server run error: %v", err)
		}
	}()

	// Block until signal.
	<-rootCtx.Done()
	stop() // release signal resources early

	// Allow up to 30 s for in-flight requests to complete.
	shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Println("Tikti shutting down…")
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}

	// Close Redis pool after HTTP drain.
	if err := application.Redis.Close(); err != nil {
		log.Printf("Redis close error: %v", err)
	}

	log.Println("Tikti stopped")
}
