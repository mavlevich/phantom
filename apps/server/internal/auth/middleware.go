package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

const currentUserContextKey = "auth.current_user"

type RouteConfig struct {
	AccessMiddleware    fiber.Handler
	RegisterLimiter     fiber.Handler
	LoginLimiter        fiber.Handler
	SessionLimiter      fiber.Handler
	RefreshCookieSecure bool
}

func CurrentUser(c *fiber.Ctx) *User {
	user, _ := c.Locals(currentUserContextKey).(*User)
	return user
}

func NewAccessMiddleware(secret string, repo Repository) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenString := bearerToken(c.Get(fiber.HeaderAuthorization))
		if tokenString == "" {
			return fiber.NewError(http.StatusUnauthorized, "missing bearer token")
		}

		claims, err := parseAccessToken(secret, tokenString, time.Now().UTC())
		if err != nil {
			return fiber.NewError(http.StatusUnauthorized, "invalid bearer token")
		}

		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			return fiber.NewError(http.StatusUnauthorized, "invalid bearer token")
		}

		// Intentionally re-load the user on every request so revocation or account
		// changes take effect immediately during alpha.
		user, err := repo.FindUserByID(c.UserContext(), userID)
		if err != nil {
			return err
		}
		if user == nil {
			return fiber.NewError(http.StatusUnauthorized, "invalid bearer token")
		}

		c.Locals(currentUserContextKey, user)
		return c.Next()
	}
}

func NewAuthRateLimiter(store SessionStore, bucketPrefix string, limit int, window time.Duration) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if store == nil {
			return c.Next()
		}

		// Alpha uses a simple fixed-window limiter in Redis. If burstiness near
		// window boundaries becomes a practical problem, we can replace this with
		// a sliding-window/Lua implementation without changing handler wiring.
		bucket := fmt.Sprintf("%s:%s", bucketPrefix, c.IP())
		allowed, err := store.AllowRequest(c.UserContext(), bucket, limit, window)
		if err != nil {
			return err
		}
		if !allowed {
			return fiber.NewError(http.StatusTooManyRequests, "too many requests")
		}

		return c.Next()
	}
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	return strings.TrimSpace(parts[1])
}

func routeHandlers(middlewares ...fiber.Handler) []fiber.Handler {
	handlers := make([]fiber.Handler, 0, len(middlewares))
	for _, middleware := range middlewares {
		if middleware != nil {
			handlers = append(handlers, middleware)
		}
	}
	return handlers
}
