package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/osvaldoandrade/tikti/internal/app"
	"github.com/osvaldoandrade/tikti/internal/repository"
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
	var kh *saml.KeyHolder
	var samlMetrics *saml.Metrics
	if cfg.SAML.Enabled {
		if err := cfg.SAML.Validate(); err != nil {
			log.Fatalf("saml config invalid: %v", err)
		}
		kh = saml.NewKeyHolder(saml.KeyHolderConfig{
			WatchFile: cfg.SAML.SP.WatchFile,
		})
		if err := kh.LoadKey(cfg.SAML.SP.SigningKeyPath, cfg.SAML.SP.SigningCertPath); err != nil {
			log.Fatalf("saml: load SP key: %v", err)
		}
		// Workers stop when rootCtx is cancelled (SIGTERM/SIGINT).
		kh.Start(rootCtx, cfg.SAML.SP.SigningKeyPath, cfg.SAML.SP.SigningCertPath)

		samlMetrics = saml.NewMetrics(prometheus.DefaultRegisterer)

		// Start background IdP metadata refresher if an interval is configured.
		if cfg.SAML.IdP.RefreshInterval > 0 {
			rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
			defer rdb.Close()
			store := saml.NewRedisStore(rdb)
			spCert, err := saml.LoadCertFile(cfg.SAML.SP.SigningCertPath)
			if err != nil {
				log.Printf("saml: could not load SP signing cert for expiry monitoring: %v", err)
			}
			saml.NewRefresher(saml.RefresherConfig{
				Store:     store,
				Metrics:   samlMetrics,
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
		application.WorkloadSvc,
	)

	application.Engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Mount SAML routes when the flag is on (HLD §16, Appendix A.1).
	// A chi router handles /saml/* paths; gin handles everything else.
	var samlRouter http.Handler
	if cfg.SAML.Enabled {
		samlStore := saml.NewRedisStore(application.Redis)
		repo := repository.NewRedisRepo(application.Redis)
		bridge := saml.NewSessionBridge(repo, application.UserService.(saml.IDTokenIssuer))

		provider := &saml.CrewjamProvider{
			EntityID: cfg.SAML.SP.EntityID,
			ACSURL:   cfg.SAML.SP.ACSURL,
			SLOURL:   cfg.SAML.SP.SLOURL,
			Key:      kh.Key(),
			Cert:     kh.Cert(),
		}

		h := saml.NewHandler(saml.Deps{
			Provider: provider,
			Store:    samlStore,
			Bridge:   bridge,
			Clock:    saml.SystemClock{},
			Cfg:      cfg.SAML,
			Metrics:  samlMetrics,
			Audit:    saml.LogEmitter{},
		})

		r := chi.NewRouter()
		r.Route("/saml", func(s chi.Router) {
			s.Use(saml.BodyLimit(1 << 20))
			s.Get("/metadata", h.Metadata)
			s.Get("/login/{tid}", h.Login)
			s.Post("/acs", h.ACS)
			s.Get("/logout/{tid}", h.Logout)
			s.Get("/slo", h.SLO)
			s.Post("/slo", h.SLO)
			s.Get("/discover", h.Discover)
		})
		samlRouter = r
		log.Println("SAML routes mounted at /saml/*")
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	var handler http.Handler = application.Engine
	if samlRouter != nil {
		ginHandler := application.Engine
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/saml/") || r.URL.Path == "/saml" {
				samlRouter.ServeHTTP(w, r)
				return
			}
			ginHandler.ServeHTTP(w, r)
		})
	}
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
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
