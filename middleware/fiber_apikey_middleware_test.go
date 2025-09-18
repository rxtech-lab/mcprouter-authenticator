package middleware

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/rxtech-lab/mcprouter-authenticator/authenticator"
	"github.com/rxtech-lab/mcprouter-authenticator/types"
)

func TestFiberApikeyMiddleware(t *testing.T) {
	t.Run("successful authentication", func(t *testing.T) {
		expectedUser := types.User{
			ID:            "user123",
			Name:          "John Doe",
			Email:         "john@example.com",
			Role:          "admin",
			EmailVerified: true,
		}

		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST request, got %s", r.Method)
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}

			var request types.ApikeyAuthenticationRequest
			if err := json.Unmarshal(body, &request); err != nil {
				t.Fatalf("failed to unmarshal request: %v", err)
			}

			if request.UserKey != "valid-user-key" {
				t.Errorf("expected userKey 'valid-user-key', got %s", request.UserKey)
			}

			response := types.ApikeyAuthenticationResult{
				User: expectedUser,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer authServer.Close()

		auth := authenticator.NewApikeyAuthenticator(authServer.URL, nil)
		middleware := FiberApikeyMiddleware(auth, "test-server-key")

		app := fiber.New()
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			user := GetUserFromContext(c)
			if user == nil {
				return c.Status(500).JSON(fiber.Map{"error": "no user in context"})
			}
			return c.JSON(fiber.Map{
				"user_id": user.ID,
				"name":    user.Name,
			})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("x-api-key", "valid-user-key")

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}

		if response["user_id"] != expectedUser.ID {
			t.Errorf("expected user_id %s, got %s", expectedUser.ID, response["user_id"])
		}
		if response["name"] != expectedUser.Name {
			t.Errorf("expected name %s, got %s", expectedUser.Name, response["name"])
		}
	})

	t.Run("missing x-api-key header", func(t *testing.T) {
		auth := authenticator.NewApikeyAuthenticator("http://example.com", nil)
		middleware := FiberApikeyMiddleware(auth, "test-server-key")

		app := fiber.New()
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "should not reach here"})
		})

		req := httptest.NewRequest("GET", "/test", nil)

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}

		if resp.StatusCode != 401 {
			t.Errorf("expected status 401, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}

		expectedError := "Missing x-api-key header"
		if response["error"] != expectedError {
			t.Errorf("expected error '%s', got '%s'", expectedError, response["error"])
		}
	})

	t.Run("empty x-api-key header", func(t *testing.T) {
		auth := authenticator.NewApikeyAuthenticator("http://example.com", nil)
		middleware := FiberApikeyMiddleware(auth, "test-server-key")

		app := fiber.New()
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "should not reach here"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("x-api-key", "")

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}

		if resp.StatusCode != 401 {
			t.Errorf("expected status 401, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}

		expectedError := "Missing x-api-key header"
		if response["error"] != expectedError {
			t.Errorf("expected error '%s', got '%s'", expectedError, response["error"])
		}
	})

	t.Run("authentication failure", func(t *testing.T) {
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
		}))
		defer authServer.Close()

		auth := authenticator.NewApikeyAuthenticator(authServer.URL, nil)
		middleware := FiberApikeyMiddleware(auth, "test-server-key")

		app := fiber.New()
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "should not reach here"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("x-api-key", "invalid-key")

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}

		if resp.StatusCode != 401 {
			t.Errorf("expected status 401, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}

		expectedError := "Authentication failed"
		if response["error"] != expectedError {
			t.Errorf("expected error '%s', got '%s'", expectedError, response["error"])
		}
	})

	t.Run("authentication server error", func(t *testing.T) {
		auth := authenticator.NewApikeyAuthenticator("http://invalid-url-that-does-not-exist", nil)
		middleware := FiberApikeyMiddleware(auth, "test-server-key")

		app := fiber.New()
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "should not reach here"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("x-api-key", "some-key")

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}

		if resp.StatusCode != 401 {
			t.Errorf("expected status 401, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}

		expectedError := "Authentication failed"
		if response["error"] != expectedError {
			t.Errorf("expected error '%s', got '%s'", expectedError, response["error"])
		}
	})
}

func TestGetUserFromContext(t *testing.T) {
	t.Run("user exists in context", func(t *testing.T) {
		expectedUser := &types.User{
			ID:            "user123",
			Name:          "John Doe",
			Email:         "john@example.com",
			Role:          "admin",
			EmailVerified: true,
		}

		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			c.Locals(UserContextKey, expectedUser)
			user := GetUserFromContext(c)

			if user == nil {
				return c.Status(500).JSON(fiber.Map{"error": "user is nil"})
			}

			return c.JSON(fiber.Map{
				"user_id": user.ID,
				"name":    user.Name,
				"email":   user.Email,
			})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}

		if response["user_id"] != expectedUser.ID {
			t.Errorf("expected user_id %s, got %s", expectedUser.ID, response["user_id"])
		}
		if response["name"] != expectedUser.Name {
			t.Errorf("expected name %s, got %s", expectedUser.Name, response["name"])
		}
		if response["email"] != expectedUser.Email {
			t.Errorf("expected email %s, got %s", expectedUser.Email, response["email"])
		}
	})

	t.Run("user does not exist in context", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			user := GetUserFromContext(c)

			if user != nil {
				return c.Status(500).JSON(fiber.Map{"error": "user should be nil"})
			}

			return c.JSON(fiber.Map{"message": "no user found"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}

		expectedMessage := "no user found"
		if response["message"] != expectedMessage {
			t.Errorf("expected message '%s', got '%s'", expectedMessage, response["message"])
		}
	})

	t.Run("wrong type in context", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			c.Locals(UserContextKey, "not a user object")
			user := GetUserFromContext(c)

			if user != nil {
				return c.Status(500).JSON(fiber.Map{"error": "user should be nil for wrong type"})
			}

			return c.JSON(fiber.Map{"message": "no valid user found"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}

		expectedMessage := "no valid user found"
		if response["message"] != expectedMessage {
			t.Errorf("expected message '%s', got '%s'", expectedMessage, response["message"])
		}
	})
}

func TestMiddlewareIntegration(t *testing.T) {
	t.Run("full integration test", func(t *testing.T) {
		expectedUser := types.User{
			ID:            "integration-user",
			Name:          "Integration Test User",
			Email:         "integration@example.com",
			Role:          "user",
			EmailVerified: false,
		}

		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var request types.ApikeyAuthenticationRequest
			json.Unmarshal(body, &request)

			response := types.ApikeyAuthenticationResult{
				User: expectedUser,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer authServer.Close()

		auth := authenticator.NewApikeyAuthenticator(authServer.URL, nil)
		middleware := FiberApikeyMiddleware(auth, "integration-server-key")

		app := fiber.New()

		// Protected route group
		protected := app.Group("/api")
		protected.Use(middleware)

		protected.Get("/profile", func(c *fiber.Ctx) error {
			user := GetUserFromContext(c)
			return c.JSON(fiber.Map{
				"profile": fiber.Map{
					"id":    user.ID,
					"name":  user.Name,
					"email": user.Email,
					"role":  user.Role,
				},
			})
		})

		protected.Post("/update", func(c *fiber.Ctx) error {
			user := GetUserFromContext(c)
			return c.JSON(fiber.Map{
				"message": fmt.Sprintf("Profile updated for user %s", user.ID),
			})
		})

		// Public route (no middleware)
		app.Get("/health", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"status": "ok"})
		})

		// Test protected route with valid key
		req := httptest.NewRequest("GET", "/api/profile", nil)
		req.Header.Set("x-api-key", "valid-integration-key")

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		// Test protected route without key
		req = httptest.NewRequest("POST", "/api/update", nil)

		resp, err = app.Test(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}

		if resp.StatusCode != 401 {
			t.Errorf("expected status 401, got %d", resp.StatusCode)
		}

		// Test public route (should work without key)
		req = httptest.NewRequest("GET", "/health", nil)

		resp, err = app.Test(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200 for public route, got %d", resp.StatusCode)
		}
	})
}
