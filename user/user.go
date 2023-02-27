package user

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/jcbbb/go-oidc/api"
	"github.com/jcbbb/go-oidc/argon"
	"github.com/jcbbb/go-oidc/db"
)

var (
	ErrUserNotFound         = api.Error{StatusCode: http.StatusNotFound, Message: "User not found", Code: "resource_not_found"}
	ErrPasswordVerification = api.Error{StatusCode: http.StatusBadRequest, Message: "Password verification faled", Code: "bad_request"}
	ErrJSONParse            = api.Error{StatusCode: http.StatusUnprocessableEntity, Message: "Unable to parse JSON body", Code: "unprocessable_entity"}
)

type Session struct {
	ID        string    `json:"id"`
	Active    bool      `json:"active"`
	ExpiresAt time.Time `json:"expires_at"`
	UserID    int       `json:"user_id"`
}

type User struct {
	ID            int    `json:"id"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Phone         string `json:"phone"`
	PhoneVerified bool   `json:"phone_verified"`
	Password      string `json:"-"`
	Verified      bool   `json:"verified"`
}

type SessionReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type NewUserReq struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	Password  string `json:"password"`
}

func New(firstName, lastName, email, phone, password string) *User {
	return &User{
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
		Phone:     phone,
		Password:  password,
	}
}

func NewSession(userId int, expiresAt time.Time) *Session {
	return &Session{
		UserID:    userId,
		ExpiresAt: expiresAt,
		Active:    true,
	}
}

func (user *User) hashPassword() error {
	hash, err := argon.Hash(user.Password)
	if err != nil {
		return nil
	}

	user.Password = hash

	return nil
}

func (user *User) verifyPassword(password string) (bool, error) {
	return argon.Verify(password, user.Password)
}

func GetAll(w http.ResponseWriter, r *http.Request) error {
	var users []User
	rows, err := db.Pool.Query(context.Background(), "select id, first_name, last_name, email, phone from users order by id desc")

	if err != nil {
		fmt.Println(err)
		return api.Error{StatusCode: 500, Message: "Something went wrong", Code: "query_err"}
	}

	defer rows.Close()

	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Phone); err != nil {
			fmt.Println(err)
			return api.Error{StatusCode: 500, Message: "Something went wrong", Code: "query_err"}
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		fmt.Println(err)
		return api.Error{StatusCode: 500, Message: "Something went wrong", Code: "query_err"}
	}

	return api.WriteJSON(w, http.StatusOK, users)
}

func Create(w http.ResponseWriter, r *http.Request) error {
	var userReq NewUserReq
	defer r.Body.Close()

	err := json.NewDecoder(r.Body).Decode(&userReq)

	if err != nil {
		return ErrJSONParse
	}

	user := New(userReq.FirstName, userReq.LastName, userReq.Email, userReq.Email, userReq.Password)

	err = user.hashPassword()
	if err != nil {
		return api.Error{StatusCode: 500, Message: "Unable to hash password", Code: "invalid_hash"}
	}

	row := db.Pool.QueryRow(
		context.Background(),
		"insert into users (first_name, last_name, email, phone, password) values ($1, $2, $3, $4, $5) returning id",
		user.FirstName, user.LastName, user.Email, user.Phone, user.Password,
	)

	if err := row.Scan(&userReq.ID); err != nil {
	}

	return api.WriteJSON(w, http.StatusCreated, user)
}

func CreateSession(w http.ResponseWriter, r *http.Request) error {
	var sessionReq SessionReq
	defer r.Body.Close()

	err := json.NewDecoder(r.Body).Decode(&sessionReq)

	if err != nil {
		return ErrJSONParse
	}

	var user User

	row := db.Pool.QueryRow(context.Background(), "select id, email, password from users where email = $1", sessionReq.Email)

	if err := row.Scan(&user.ID, &user.Email, &user.Password); err != nil {
		if err == sql.ErrNoRows {
			return ErrUserNotFound
		}
		return api.Error{StatusCode: 500, Message: "Internal error", Code: "internal_error"}
	}

	match, err := user.verifyPassword(sessionReq.Password)

	if err != nil || !match {
		return ErrPasswordVerification
	}

	session := NewSession(user.ID, time.Now().AddDate(0, 6, 0))

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	row = db.Pool.QueryRow(context.Background(), "insert into sessions (user_id, expires_at, ip) values ($1, $2, $3) returning id", session.UserID, session.ExpiresAt, host)

	if err := row.Scan(&session.ID); err != nil {
		return api.Error{StatusCode: 500, Message: err.Error(), Code: "internal_error"}
	}

	return api.WriteJSON(w, http.StatusOK, session)
}

// // func createClient(w http.ResponseWriter, r *http.Request) error {
// // 	var client Client
// // 	defer r.Body.Close()
// // 	err := json.NewDecoder(r.Body).Decode(&client)

// // 	if err != nil {
// // 		return ApiError{StatusCode: 400, Message: "Unable to decode json body", Code: "invalid_json"}
// // 	}

// // 	w.Header().Set("Content-Type", "application/json")
// // 	w.WriteHeader(200)
// // 	return json.NewEncoder(w).Encode(client)
// }
