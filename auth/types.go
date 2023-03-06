package auth

import (
	"time"
)

type Session struct {
	ID        string    `json:"id"`
	Active    bool      `json:"active"`
	ExpiresAt time.Time `json:"expires_at"`
	UserID    int       `json:"user_id"`
}

type LoginReq struct {
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type oauthResponseType string

const (
	CodeResponseType  oauthResponseType = "code"
	TokenResponseType oauthResponseType = "token"
)

type AuthorizationReq struct {
	ResponseType        oauthResponseType
	ClientID            string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectURI         string
	Scope               string
	State               string
}

type AuthorizationResponse struct {
	Code  int
	State string
	ISS   string
}
