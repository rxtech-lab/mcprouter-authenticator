package authenticator

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rxtech-lab/mcprouter-authenticator/types"
)

func TestNewApikeyAuthenticator(t *testing.T) {
	t.Run("with custom http client", func(t *testing.T) {
		customClient := &http.Client{}
		auth := NewApikeyAuthenticator("http://example.com", customClient)

		if auth.url != "http://example.com" {
			t.Errorf("expected url to be 'http://example.com', got %s", auth.url)
		}
		if auth.httpClient != customClient {
			t.Error("expected custom http client to be used")
		}
	})

	t.Run("with nil http client", func(t *testing.T) {
		auth := NewApikeyAuthenticator("http://example.com", nil)

		if auth.url != "http://example.com" {
			t.Errorf("expected url to be 'http://example.com', got %s", auth.url)
		}
		if auth.httpClient == nil {
			t.Error("expected default http client to be created")
		}
	})
}

func TestApikeyAuthenticator_Authenticate(t *testing.T) {
	t.Run("successful authentication", func(t *testing.T) {
		expectedUser := types.User{
			ID:            "user123",
			Name:          "John Doe",
			Email:         "john@example.com",
			Role:          "admin",
			EmailVerified: true,
		}

		response := types.ApikeyAuthenticationResult{
			User: expectedUser,
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST request, got %s", r.Method)
			}

			if r.Header.Get("x-api-key") != "test-server-key" {
				t.Errorf("expected x-api-key 'test-server-key', got %s", r.Header.Get("x-api-key"))
			}

			if r.URL.Path != "/api/auth/mcp/session" {
				t.Errorf("expected path '/api/auth/mcp/session', got %s", r.URL.Path)
			}

			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("expected Content-Type 'application/json', got %s", r.Header.Get("Content-Type"))
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}

			var request types.ApikeyAuthenticationRequest
			if err := json.Unmarshal(body, &request); err != nil {
				t.Fatalf("failed to unmarshal request: %v", err)
			}

			if request.UserKey != "test-user-key" {
				t.Errorf("expected userKey 'test-user-key', got %s", request.UserKey)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		auth := NewApikeyAuthenticator(server.URL, nil)
		user, err := auth.Authenticate("test-server-key", "test-user-key")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if user.ID != expectedUser.ID {
			t.Errorf("expected user ID %s, got %s", expectedUser.ID, user.ID)
		}
		if user.Name != expectedUser.Name {
			t.Errorf("expected user name %s, got %s", expectedUser.Name, user.Name)
		}
		if user.Email != expectedUser.Email {
			t.Errorf("expected user email %s, got %s", expectedUser.Email, user.Email)
		}
		if user.Role != expectedUser.Role {
			t.Errorf("expected user role %s, got %s", expectedUser.Role, user.Role)
		}
		if user.EmailVerified != expectedUser.EmailVerified {
			t.Errorf("expected emailVerified %t, got %t", expectedUser.EmailVerified, user.EmailVerified)
		}
	})

	t.Run("http request error", func(t *testing.T) {
		auth := NewApikeyAuthenticator("http://invalid-url", nil)
		user, err := auth.Authenticate("test-server-key", "test-user-key")

		if err == nil {
			t.Error("expected error for invalid URL")
		}
		if user != nil {
			t.Error("expected nil user on error")
		}
	})

	t.Run("invalid json response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		auth := NewApikeyAuthenticator(server.URL, nil)
		user, err := auth.Authenticate("test-server-key", "test-user-key")

		if err == nil {
			t.Error("expected error for invalid JSON")
		}
		if user != nil {
			t.Error("expected nil user on error")
		}
	})

	t.Run("http error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
		}))
		defer server.Close()

		auth := NewApikeyAuthenticator(server.URL, nil)
		user, err := auth.Authenticate("test-server-key", "test-user-key")

		if err == nil {
			t.Error("expected error for HTTP error status")
		}
		if user != nil {
			t.Error("expected nil user on error")
		}
	})
}

type mockRoundTripper struct {
	responseFunc func(*http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.responseFunc(req)
}

func TestApikeyAuthenticator_Authenticate_RequestValidation(t *testing.T) {
	t.Run("validates request format", func(t *testing.T) {
		var capturedRequest *http.Request

		client := &http.Client{
			Transport: &mockRoundTripper{
				responseFunc: func(req *http.Request) (*http.Response, error) {
					capturedRequest = req

					response := types.ApikeyAuthenticationResult{
						User: types.User{ID: "test"},
					}
					responseBody, _ := json.Marshal(response)

					return &http.Response{
						StatusCode: 200,
						Body:       io.NopCloser(strings.NewReader(string(responseBody))),
						Header:     make(http.Header),
					}, nil
				},
			},
		}

		auth := NewApikeyAuthenticator("http://example.com", client)
		auth.Authenticate("server-key", "user-key")

		if capturedRequest == nil {
			t.Fatal("request was not captured")
		}

		if capturedRequest.URL.String() != "http://example.com/api/auth/mcp/session" {
			t.Errorf("unexpected URL: %s", capturedRequest.URL.String())
		}

		if capturedRequest.Method != "POST" {
			t.Errorf("expected POST method, got %s", capturedRequest.Method)
		}

		body, _ := io.ReadAll(capturedRequest.Body)
		var request types.ApikeyAuthenticationRequest
		json.Unmarshal(body, &request)

		if request.UserKey != "user-key" {
			t.Errorf("expected userKey 'user-key', got %s", request.UserKey)
		}
	})
}
