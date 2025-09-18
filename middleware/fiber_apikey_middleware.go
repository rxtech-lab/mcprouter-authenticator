package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rxtech-lab/mcprouter-authenticator/authenticator"
	"github.com/rxtech-lab/mcprouter-authenticator/types"
)

type OnAuthenticationSuccess func(c *fiber.Ctx, user *types.User) error

// OnAuthenticationSuccess is a function that is called when the authentication is successful
// You can use onAuthenticationSuccess to add the user to the context
func FiberApikeyMiddleware(auth *authenticator.ApikeyAuthenticator, serverKey string, onAuthenticationSuccess OnAuthenticationSuccess) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userKeyFromHeader := c.Get("x-api-key")
		userKeyFromQuery := c.Query("api-key")
		if userKeyFromHeader == "" && userKeyFromQuery == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Missing x-api-key header",
			})
		}

		userKey := userKeyFromHeader
		if userKeyFromQuery != "" {
			userKey = userKeyFromQuery
		}

		user, err := auth.Authenticate(serverKey, userKey)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authentication failed",
			})
		}

		if onAuthenticationSuccess != nil {
			onAuthenticationSuccess(c, user)
		}
		return c.Next()
	}
}
