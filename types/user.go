package types

type User struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Email         string  `json:"email"`
	Role          string  `json:"role"`
	EmailVerified *string `json:"emailVerified,omitempty"`
}

type ApikeyAuthenticationResult struct {
	User User `json:"user"`
}

type ApikeyAuthenticationRequest struct {
	UserKey string `json:"userKey"`
}
