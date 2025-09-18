package types

// {
// 	id: user.id,
// 	name: user.name,
// 	email: user.email,
// 	role: user.role,
// 	emailVerified: user.emailVerified,
//   }

type User struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	Role          string `json:"role"`
	EmailVerified bool   `json:"emailVerified"`
}

type ApikeyAuthenticationResult struct {
	User User `json:"user"`
}

type ApikeyAuthenticationRequest struct {
	UserKey string `json:"userKey"`
}
