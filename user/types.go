package user

import "time"

type Session struct {
	ID        string    `json:"id"`
	Active    bool      `json:"active"`
	ExpiresAt time.Time `json:"expires_at"`
	UserID    uint      `json:"user_id"`
}

type User struct {
	ID            uint   `json:"id"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Phone         string `json:"phone"`
	PhoneVerified bool   `json:"phone_verified"`
	Password      string `json:"-"`
	Verified      bool   `json:"verified"`
}

type SessionReq struct {
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type NewUserReq struct {
	ID        uint   `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	Password  string `json:"password"`
	Picture   string `json:"picture"`
}
