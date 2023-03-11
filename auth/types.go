package auth

import (
	"time"

	"github.com/jcbbb/go-oidc/client"
)

type Session struct {
	ID        string    `json:"id"`
	Active    bool      `json:"active"`
	ExpiresAt time.Time `json:"expires_at"`
	UserID    uint      `json:"user_id"`
}

type LoginReq struct {
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type AuthorizationReq struct {
	ID                  uint
	ResponseType        string
	Client              *client.Client
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectURI         string
	Scopes              []client.Scope
	State               string
	UserID              uint
	Code                string
	ExpiresAt           time.Time
}

type Permission struct {
	Scope   string
	Name    string
	IconURI string
}

type TokenReq struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type AccessToken struct {
	Iss      string    `json:"iss"`
	Exp      string    `json:"exp"`
	Aud      string    `json:"aud"`
	ClientID string    `json:"client_id"`
	Iat      time.Time `json:"iat"`
	Jti      string    `json:"jti"`
	Scope    string    `json:"scope"`
}
