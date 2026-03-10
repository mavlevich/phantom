package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"

		"github.com/yourusername/phantom/server/config"
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

	// TODO: wire routes
	// httpRouter := http.NewRouter(authService, userService, ...)
	// httpRouter.Register(app)
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

func errorHandler(env string) fiber.ErrorHandler {
	return func(c *fiber.Ctx, err error) error {
		code := fiber.StatusInternalServerError
		msg := "internal server error"

		if e, ok := err.(*fiber.Error); ok {
			code = e.Code
			msg = e.Message
		}

		// In production, never leak internal error details
		if env == "production" && code == fiber.StatusInternalServerError {
			msg = "internal server error"
		} else if env != "production" {
			msg = err.Error()
		}

		return c.Status(code).JSON(fiber.Map{
			"data":  nil,
			"error": msg,
		})
	}
}
