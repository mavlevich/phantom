package auth

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

const refreshTokenCookieName = "phantom_refresh_token"

func setRefreshTokenCookie(c *fiber.Ctx, token string, expiresAt time.Time, secure bool) {
	c.Cookie(&fiber.Cookie{
		Name:     refreshTokenCookieName,
		Value:    token,
		Path:     "/api/v1/auth",
		HTTPOnly: true,
		Secure:   secure,
		SameSite: fiber.CookieSameSiteStrictMode,
		Expires:  expiresAt,
	})
}

func clearRefreshTokenCookie(c *fiber.Ctx, secure bool) {
	c.Cookie(&fiber.Cookie{
		Name:     refreshTokenCookieName,
		Value:    "",
		Path:     "/api/v1/auth",
		HTTPOnly: true,
		Secure:   secure,
		SameSite: fiber.CookieSameSiteStrictMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}
