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

	"github.com/mavlevich/phantom/server/config"
	"github.com/mavlevich/phantom/server/internal/auth"
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

	authRepo := auth.NewPostgresRepository(db)
	authService := auth.NewService(authRepo)

	app := fiber.New(fiber.Config{
		AppName:      "Phantom",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		// Never expose error details to client in production
		ErrorHandler: errorHandler(cfg.Env),
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
	auth.RegisterRoutes(api, authService)

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

func errorHandler(env string) fiber.ErrorHandler {
	return func(c *fiber.Ctx, err error) error {
		code := fiber.StatusInternalServerError
		msg := "internal server error"

		if e, ok := err.(*fiber.Error); ok {
			code = e.Code
			msg = e.Message
		}

		if code >= fiber.StatusInternalServerError {
			slog.Error("request failed", "env", env, "path", c.Path(), "error", err)
			msg = "internal server error"
		}

		return c.Status(code).JSON(fiber.Map{
			"data":  nil,
			"error": msg,
		})
	}
}
