# MCProuter Authenticator

A Go package that provides API key authentication for MCProuter applications, with built-in Fiber middleware support.

## Overview

The `mcprouter-authenticator` package provides a simple and secure way to authenticate users via API keys in your Go applications. It includes:

- **API Key Authenticator**: Core authentication logic that validates API keys against a remote authentication service
- **Fiber Middleware**: Ready-to-use middleware for Fiber web framework applications
- **Type Definitions**: Structured types for users and authentication requests/responses

## Installation

```bash
go get github.com/rxtech-lab/mcprouter-authenticator
```

## Quick Start

### Basic Usage with Fiber

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/rxtech-lab/mcprouter-authenticator/authenticator"
    "github.com/rxtech-lab/mcprouter-authenticator/middleware"
    "github.com/rxtech-lab/mcprouter-authenticator/types"
)

func main() {
    // Create authenticator instance
    auth := authenticator.NewApikeyAuthenticator("https://your-auth-server.com", nil)

    // Create Fiber app
    app := fiber.New()

    // Add authentication middleware
    app.Use(middleware.FiberApikeyMiddleware(auth, "your-server-key", func(c *fiber.Ctx, user *types.User) error {
        // Store user in context for later use
        c.Locals("user", user)
        return nil
    }))

    // Protected route
    app.Get("/profile", func(c *fiber.Ctx) error {
        user := middleware.GetUserFromContext(c)
        if user == nil {
            return c.Status(500).JSON(fiber.Map{"error": "no user found"})
        }

        return c.JSON(fiber.Map{
            "id":    user.ID,
            "name":  user.Name,
            "email": user.Email,
            "role":  user.Role,
        })
    })

    app.Listen(":3000")
}
```

### Making Authenticated Requests

Clients should include the API key in the `x-api-key` header:

```bash
curl -H "x-api-key: your-user-api-key" http://localhost:3000/profile
```

## Components

### 1. Authenticator (`authenticator` package)

The core authentication component that validates API keys against a remote service.

#### `ApikeyAuthenticator`

```go
type ApikeyAuthenticator struct {
    // Internal fields
}

// Create a new authenticator instance
func NewApikeyAuthenticator(url string, httpClient *http.Client) *ApikeyAuthenticator

// Authenticate a user with server key and user API key
func (a *ApikeyAuthenticator) Authenticate(serverKey string, userKey string) (*types.User, error)
```

**Parameters:**

- `url`: Base URL of your authentication service
- `httpClient`: Optional custom HTTP client (uses default if nil)
- `serverKey`: Server-side key for authentication service
- `userKey`: User's API key to validate

**Authentication Endpoint:**
The authenticator makes POST requests to `{url}/api/auth/mcp/session` with the user's API key.

### 2. Middleware (`middleware` package)

Fiber middleware for seamless integration with web applications.

#### `FiberApikeyMiddleware`

```go
func FiberApikeyMiddleware(
    auth *authenticator.ApikeyAuthenticator,
    serverKey string,
    onAuthenticationSuccess OnAuthenticationSuccess
) fiber.Handler
```

**Parameters:**

- `auth`: Authenticator instance
- `serverKey`: Server key for authentication
- `onAuthenticationSuccess`: Callback function executed when authentication succeeds

**Callback Function:**

```go
type OnAuthenticationSuccess func(c *fiber.Ctx, user *types.User) error
```

Use this callback to store the authenticated user in the Fiber context or perform other post-authentication actions.

#### Helper Functions

```go
// Retrieve user from Fiber context
func GetUserFromContext(c *fiber.Ctx) *types.User
```

### 3. Types (`types` package)

Data structures for users and authentication.

#### `User`

```go
type User struct {
    ID            string `json:"id"`
    Name          string `json:"name"`
    Email         string `json:"email"`
    Role          string `json:"role"`
    EmailVerified bool   `json:"emailVerified"`
}
```

#### Authentication Types

```go
type ApikeyAuthenticationRequest struct {
    UserKey string `json:"userKey"`
}

type ApikeyAuthenticationResult struct {
    User User `json:"user"`
}
```

## Authentication Flow

1. **Client Request**: Client sends request with `x-api-key` header
2. **Middleware Validation**: Fiber middleware extracts and validates the API key
3. **Remote Authentication**: Authenticator sends POST request to authentication service
4. **User Retrieval**: On success, user information is returned and stored in context
5. **Request Processing**: Request continues to your application handlers

## Error Handling

The middleware returns appropriate HTTP status codes:

- **401 Unauthorized**: Missing or invalid API key
- **401 Unauthorized**: Authentication service error or rejection

Error responses are in JSON format:

```json
{
  "error": "Missing x-api-key header"
}
```

or

```json
{
  "error": "Authentication failed"
}
```

## Advanced Usage

### Custom HTTP Client

You can provide a custom HTTP client for the authenticator:

```go
import (
    "net/http"
    "time"
)

client := &http.Client{
    Timeout: 10 * time.Second,
    Transport: &http.Transport{
        MaxIdleConns: 100,
    },
}

auth := authenticator.NewApikeyAuthenticator("https://auth-server.com", client)
```

### Route Groups

Apply middleware to specific route groups:

```go
app := fiber.New()

// Public routes
app.Get("/health", healthHandler)

// Protected routes
api := app.Group("/api")
api.Use(middleware.FiberApikeyMiddleware(auth, serverKey, addUserToContext))

api.Get("/users", getUsersHandler)
api.Post("/users", createUserHandler)
```

### Custom Authentication Success Handler

```go
func customAuthHandler(c *fiber.Ctx, user *types.User) error {
    // Log authentication
    log.Printf("User %s (%s) authenticated", user.Name, user.ID)

    // Store in context
    c.Locals("user", user)
    c.Locals("user_role", user.Role)

    // Add custom headers
    c.Set("X-User-ID", user.ID)

    return nil
}

middleware := middleware.FiberApikeyMiddleware(auth, serverKey, customAuthHandler)
```

## Testing

The package includes comprehensive tests. Run them with:

```bash
go test ./...
```

For verbose output:

```bash
go test -v ./...
```

## Requirements

- Go 1.25.0 or later
- Fiber v2.52.9 or compatible version

## Dependencies

- `github.com/gofiber/fiber/v2`: Web framework
- Standard library packages for HTTP and JSON handling

## License

This package is part of the RXTech Lab ecosystem. Please refer to your organization's licensing terms.

## Contributing

When contributing to this package:

1. Ensure all tests pass
2. Add tests for new functionality
3. Follow Go coding standards
4. Update documentation as needed

## Support

For issues and questions related to this package, please contact the RXTech Lab development team.
