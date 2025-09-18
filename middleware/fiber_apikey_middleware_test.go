package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/rxtech-lab/mcprouter-authenticator/authenticator"
	"github.com/rxtech-lab/mcprouter-authenticator/types"
)

func TestFiberApikeyMiddleware(t *testing.T) {
	t.Run("no api key in header or query - should skip auth", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("should not call auth server when no api key provided")
		}))
		defer mockServer.Close()

		auth := authenticator.NewApikeyAuthenticator(mockServer.URL, nil)
		app := fiber.New()

		middleware := FiberApikeyMiddleware(auth, "server-key", nil)
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("api key in header - successful authentication", func(t *testing.T) {
		expectedUser := types.User{
			ID:    "user123",
			Name:  "John Doe",
			Email: "john@example.com",
			Role:  "admin",
		}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("x-api-key") != "server-key" {
				t.Errorf("expected server key 'server-key', got %s", r.Header.Get("x-api-key"))
			}

			response := types.ApikeyAuthenticationResult{
				User: expectedUser,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer mockServer.Close()

		auth := authenticator.NewApikeyAuthenticator(mockServer.URL, nil)
		app := fiber.New()

		var capturedUser *types.User
		onSuccess := func(c *fiber.Ctx, user *types.User) error {
			capturedUser = user
			return nil
		}

		middleware := FiberApikeyMiddleware(auth, "server-key", onSuccess)
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("x-api-key", "user-key")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		if capturedUser == nil {
			t.Error("expected user to be captured in success callback")
		} else {
			if capturedUser.ID != expectedUser.ID {
				t.Errorf("expected user ID %s, got %s", expectedUser.ID, capturedUser.ID)
			}
		}
	})

	t.Run("api key in query parameter - successful authentication", func(t *testing.T) {
		expectedUser := types.User{
			ID:    "user456",
			Name:  "Jane Doe",
			Email: "jane@example.com",
			Role:  "user",
		}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := types.ApikeyAuthenticationResult{
				User: expectedUser,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer mockServer.Close()

		auth := authenticator.NewApikeyAuthenticator(mockServer.URL, nil)
		app := fiber.New()

		var capturedUser *types.User
		onSuccess := func(c *fiber.Ctx, user *types.User) error {
			capturedUser = user
			return nil
		}

		middleware := FiberApikeyMiddleware(auth, "server-key", onSuccess)
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test?api-key=user-query-key", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		if capturedUser == nil {
			t.Error("expected user to be captured in success callback")
		} else {
			if capturedUser.ID != expectedUser.ID {
				t.Errorf("expected user ID %s, got %s", expectedUser.ID, capturedUser.ID)
			}
		}
	})

	t.Run("query parameter takes precedence over header", func(t *testing.T) {
		var capturedUserKey string
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var request types.ApikeyAuthenticationRequest
			json.Unmarshal(body, &request)
			capturedUserKey = request.UserKey

			response := types.ApikeyAuthenticationResult{
				User: types.User{ID: "test"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer mockServer.Close()

		auth := authenticator.NewApikeyAuthenticator(mockServer.URL, nil)
		app := fiber.New()

		middleware := FiberApikeyMiddleware(auth, "server-key", nil)
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test?api-key=query-key", nil)
		req.Header.Set("x-api-key", "header-key")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		if capturedUserKey != "query-key" {
			t.Errorf("expected query key to be used, got %s", capturedUserKey)
		}
	})

	t.Run("query parameter used when header is empty", func(t *testing.T) {
		var capturedUserKey string
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var request types.ApikeyAuthenticationRequest
			json.Unmarshal(body, &request)
			capturedUserKey = request.UserKey

			response := types.ApikeyAuthenticationResult{
				User: types.User{ID: "test"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer mockServer.Close()

		auth := authenticator.NewApikeyAuthenticator(mockServer.URL, nil)
		app := fiber.New()

		middleware := FiberApikeyMiddleware(auth, "server-key", nil)
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test?api-key=query-only-key", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		if capturedUserKey != "query-only-key" {
			t.Errorf("expected query key to be used, got %s", capturedUserKey)
		}
	})

	t.Run("authentication failure - returns 401", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
		}))
		defer mockServer.Close()

		auth := authenticator.NewApikeyAuthenticator(mockServer.URL, nil)
		app := fiber.New()

		middleware := FiberApikeyMiddleware(auth, "server-key", nil)
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("x-api-key", "invalid-key")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.StatusCode != 401 {
			t.Errorf("expected status 401, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		var response map[string]interface{}
		json.Unmarshal(body, &response)

		if response["error"] != "Authentication failed" {
			t.Errorf("expected error message 'Authentication failed', got %v", response["error"])
		}
	})

	t.Run("nil onAuthenticationSuccess callback", func(t *testing.T) {
		expectedUser := types.User{
			ID:    "user789",
			Name:  "Bob Smith",
			Email: "bob@example.com",
			Role:  "user",
		}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := types.ApikeyAuthenticationResult{
				User: expectedUser,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer mockServer.Close()

		auth := authenticator.NewApikeyAuthenticator(mockServer.URL, nil)
		app := fiber.New()

		middleware := FiberApikeyMiddleware(auth, "server-key", nil)
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("x-api-key", "user-key")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("onAuthenticationSuccess callback executes without error", func(t *testing.T) {
		expectedUser := types.User{
			ID:    "user999",
			Name:  "Success User",
			Email: "success@example.com",
			Role:  "user",
		}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := types.ApikeyAuthenticationResult{
				User: expectedUser,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer mockServer.Close()

		auth := authenticator.NewApikeyAuthenticator(mockServer.URL, nil)
		app := fiber.New()

		callbackCalled := false
		onSuccess := func(c *fiber.Ctx, user *types.User) error {
			callbackCalled = true
			return nil
		}

		middleware := FiberApikeyMiddleware(auth, "server-key", onSuccess)
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("x-api-key", "user-key")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		if !callbackCalled {
			t.Error("expected callback to be called")
		}
	})
}