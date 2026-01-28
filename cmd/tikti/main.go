package main

import (
	"flag"
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/app"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

var configFile = flag.String("f", "config/tikti.yaml", "Path to the YAML config file")

func main() {
	flag.Parse()

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
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
