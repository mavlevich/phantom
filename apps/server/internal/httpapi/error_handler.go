package httpapi

import (
	"log/slog"

	"github.com/gofiber/fiber/v2"
)

func ErrorHandler(logger *slog.Logger, env string) fiber.ErrorHandler {
	if logger == nil {
		logger = slog.Default()
	}

	return func(c *fiber.Ctx, err error) error {
		code := fiber.StatusInternalServerError
		msg := "internal server error"

		if e, ok := err.(*fiber.Error); ok {
			code = e.Code
			msg = e.Message
		}

		if code >= fiber.StatusInternalServerError {
			logger.Error("request failed", "env", env, "path", c.Path(), "error", err)
			msg = "internal server error"
		}

		return c.Status(code).JSON(fiber.Map{
			"data":  nil,
			"error": msg,
		})
	}
}
