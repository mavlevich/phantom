package auth

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

func RegisterRoutes(router fiber.Router, service Service, configs ...RouteConfig) {
	cfg := RouteConfig{}
	if len(configs) > 0 {
		cfg = configs[0]
	}

	authGroup := router.Group("/auth")
	authGroup.Post("/register", routeHandlers(cfg.RegisterLimiter, registerHandler(service))...)
	authGroup.Post("/login", routeHandlers(cfg.LoginLimiter, loginHandler(service, cfg.RefreshCookieSecure))...)
	authGroup.Post("/refresh", routeHandlers(cfg.SessionLimiter, refreshHandler(service, cfg.RefreshCookieSecure))...)
	authGroup.Post("/logout", routeHandlers(cfg.SessionLimiter, logoutHandler(service, cfg.RefreshCookieSecure))...)
	authGroup.Get("/me", routeHandlers(cfg.AccessMiddleware, meHandler())...)
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

func loginHandler(service Service, refreshCookieSecure bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var input LoginInput
		if err := c.BodyParser(&input); err != nil {
			return fiber.NewError(http.StatusBadRequest, "invalid request body")
		}

		result, err := service.Login(c.UserContext(), input)
		if err != nil {
			return mapLoginError(err)
		}

		setRefreshTokenCookie(c, result.RefreshToken, result.RefreshExpiresAt, refreshCookieSecure)
		return c.Status(http.StatusOK).JSON(fiber.Map{
			"data":  result,
			"error": nil,
		})
	}
}

func refreshHandler(service Service, refreshCookieSecure bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		result, err := service.Refresh(c.UserContext(), RefreshInput{
			RefreshToken: c.Cookies(refreshTokenCookieName),
		})
		if err != nil {
			return mapRefreshError(err)
		}

		setRefreshTokenCookie(c, result.RefreshToken, result.RefreshExpiresAt, refreshCookieSecure)
		return c.Status(http.StatusOK).JSON(fiber.Map{
			"data":  result,
			"error": nil,
		})
	}
}

func logoutHandler(service Service, refreshCookieSecure bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := service.Logout(c.UserContext(), LogoutInput{
			RefreshToken: c.Cookies(refreshTokenCookieName),
		}); err != nil {
			return err
		}

		clearRefreshTokenCookie(c, refreshCookieSecure)
		return c.SendStatus(http.StatusNoContent)
	}
}

func meHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := CurrentUser(c)
		if user == nil {
			return fiber.NewError(http.StatusUnauthorized, "invalid bearer token")
		}

		return c.Status(http.StatusOK).JSON(fiber.Map{
			"data": fiber.Map{
				"user_id":  user.ID,
				"username": user.Username,
			},
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

func mapLoginError(err error) error {
	switch {
	case errors.Is(err, ErrAccountLocked):
		return fiber.NewError(http.StatusUnauthorized, "invalid username or password")
	case errors.Is(err, ErrInvalidCredentials):
		return fiber.NewError(http.StatusUnauthorized, "invalid username or password")
	default:
		return err
	}
}

func mapRefreshError(err error) error {
	switch {
	case errors.Is(err, ErrTokenInvalid), errors.Is(err, ErrTokenExpired):
		return fiber.NewError(http.StatusUnauthorized, "invalid refresh token")
	default:
		return err
	}
}
