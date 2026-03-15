package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	"github.com/mavlevich/phantom/server/config"
	"github.com/mavlevich/phantom/server/internal/auth"
	"github.com/mavlevich/phantom/server/internal/httpapi"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(log)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	db, err := openDatabase(cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to connect database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	redisClient, err := openRedis(cfg.RedisURL)
	if err != nil {
		slog.Error("failed to connect redis", "error", err)
		os.Exit(1)
	}
	defer func() {
		_ = redisClient.Close()
	}()

	authRepo := auth.NewPostgresRepository(db)
	sessionStore := auth.NewRedisSessionStore(redisClient)
	authService := auth.NewService(authRepo, auth.ServiceConfig{
		JWTSecret:          cfg.JWTSecret,
		JWTExpiry:          cfg.JWTExpiry,
		RefreshTokenExpiry: cfg.RefreshTokenExpiry,
		SessionStore:       sessionStore,
	})

	app := fiber.New(fiber.Config{
		AppName:      "Phantom",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		// Never expose error details to client in production
		ErrorHandler: httpapi.ErrorHandler(slog.Default(), cfg.Env),
	})

	// Middleware
	app.Use(recover.New())
	app.Use(requestid.New())
	app.Use(logger.New(logger.Config{
		// SECURITY: never log request body (may contain encrypted payloads or credentials)
		Format: "[${time}] ${status} ${method} ${path} ${latency} rid=${locals:requestid}\n",
	}))

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	api := app.Group("/api/v1")
	auth.RegisterRoutes(api, authService, auth.RouteConfig{
		AccessMiddleware:    auth.NewAccessMiddleware(cfg.JWTSecret, authRepo),
		RegisterLimiter:     auth.NewAuthRateLimiter(sessionStore, "register", 5, time.Minute),
		LoginLimiter:        auth.NewAuthRateLimiter(sessionStore, "login", 5, time.Minute),
		SessionLimiter:      auth.NewAuthRateLimiter(sessionStore, "session", 20, time.Minute),
		RefreshCookieSecure: cfg.IsProduction(),
	})

	// wsRouter := ws.NewRouter(hub)
	// wsRouter.Register(app)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("starting server", "port", cfg.ServerPort, "env", cfg.Env)
		if err := app.Listen(":" + cfg.ServerPort); err != nil {
			slog.Error("server error", "error", err)
		}
	}()

	<-quit
	slog.Info("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := app.ShutdownWithContext(ctx); err != nil {
		slog.Error("forced shutdown", "error", err)
	}

	slog.Info("server stopped")
}

func openDatabase(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

func openRedis(redisURL string) (*redis.Client, error) {
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(options)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}

	return client, nil
}
