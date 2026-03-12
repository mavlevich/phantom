package auth

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

func RegisterRoutes(router fiber.Router, service Service) {
	authGroup := router.Group("/auth")
	authGroup.Post("/register", registerHandler(service))
}

func registerHandler(service Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var input RegisterInput
		if err := c.BodyParser(&input); err != nil {
			return fiber.NewError(http.StatusBadRequest, "invalid request body")
		}

		result, err := service.Register(c.UserContext(), input)
		if err != nil {
			return mapRegisterError(err)
		}

		return c.Status(http.StatusCreated).JSON(fiber.Map{
			"data":  result,
			"error": nil,
		})
	}
}

func mapRegisterError(err error) error {
	switch {
	case errors.Is(err, ErrUserAlreadyExists):
		return fiber.NewError(http.StatusConflict, "username is already taken")
	case errors.Is(err, ErrInviteNotFound), errors.Is(err, ErrInviteAlreadyUsed), errors.Is(err, ErrInviteExpired):
		return fiber.NewError(http.StatusBadRequest, "invalid or unavailable invite code")
	case errors.Is(err, ErrInvalidUsername):
		return fiber.NewError(http.StatusBadRequest, "invalid username")
	case errors.Is(err, ErrWeakPassword):
		return fiber.NewError(http.StatusBadRequest, "password must be at least 12 characters")
	case errors.Is(err, ErrInvalidPublicKey):
		return fiber.NewError(http.StatusBadRequest, "invalid public key")
	default:
		return err
	}
}
