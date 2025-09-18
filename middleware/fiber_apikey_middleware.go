package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rxtech-lab/mcprouter-authenticator/authenticator"
	"github.com/rxtech-lab/mcprouter-authenticator/types"
)

const UserContextKey = "user"

func FiberApikeyMiddleware(auth *authenticator.ApikeyAuthenticator, serverKey string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userKey := c.Get("x-api-key")
		if userKey == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Missing x-api-key header",
			})
		}

		user, err := auth.Authenticate(serverKey, userKey)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authentication failed",
			})
		}

		c.Locals(UserContextKey, user)
		return c.Next()
	}
}

func GetUserFromContext(c *fiber.Ctx) *types.User {
	user, ok := c.Locals(UserContextKey).(*types.User)
	if !ok {
		return nil
	}
	return user
}
