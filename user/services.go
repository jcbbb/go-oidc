package user

import (
	"context"
	"database/sql"
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

func getAll() (*[]User, error) {
	var users []User
	rows, err := db.Pool.Query(context.Background(), "select id, first_name, last_name, email, phone from users order by id desc")

	if err != nil {
		fmt.Println(err)
		return nil, api.Error{StatusCode: 500, Message: "Something went wrong", Code: "query_err"}
	}

	defer rows.Close()

	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Phone); err != nil {
			fmt.Println(err)
			return nil, api.Error{StatusCode: 500, Message: "Something went wrong", Code: "query_err"}
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		fmt.Println(err)
		return nil, api.Error{StatusCode: 500, Message: "Something went wrong", Code: "query_err"}
	}

	return &users, nil
}

func create(req NewUserReq) (*User, error) {
	user := New(req.FirstName, req.LastName, req.Email, req.Phone, req.Password)
	err := user.hashPassword()
	if err != nil {
		return nil, api.Error{StatusCode: 500, Message: "Unable to hash password", Code: "invalid_hash"}
	}

	row := db.Pool.QueryRow(
		context.Background(),
		"insert into users (first_name, last_name, email, phone, password) values ($1, $2, $3, $4, $5) returning id",
		user.FirstName, user.LastName, user.Email, user.Phone, user.Password,
	)

	if err := row.Scan(&req.ID); err != nil {
	}

	return user, nil
}

func getSession(sid string) (Session, error) {
	var session Session
	row := db.Pool.QueryRow(context.Background(), "select id, user_id, expires_at, active from sessions where id = $1", sid)

	if err := row.Scan(&session.ID, &session.UserID, &session.ExpiresAt, &session.Active); err != nil {
		return session, api.Error{StatusCode: 500, Message: err.Error(), Code: "internal_error"}
	}

	return session, nil
}

func getUser(userId int) (*User, error) {
	var user User

	row := db.Pool.QueryRow(context.Background(), "select id, email, phone, first_name, last_name, email_verified, phone_verified, verified from users where id = $1", userId)

	if err := row.Scan(&user.ID, &user.Email, &user.Phone, &user.FirstName, &user.LastName, &user.EmailVerified, &user.PhoneVerified, &user.Verified); err != nil {
		fmt.Println(err)
		return nil, api.Error{StatusCode: 500, Message: "Internal error", Code: "internal_error"}
	}

	return &user, nil
}

func createSession(req SessionReq, remoteAddr string) (*Session, error) {
	var user User

	row := db.Pool.QueryRow(context.Background(), "select id, email, password from users where email = $1", req.Email)

	if err := row.Scan(&user.ID, &user.Email, &user.Password); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, api.Error{StatusCode: 500, Message: "Internal error", Code: "internal_error"}
	}

	match, err := user.verifyPassword(req.Password)

	if err != nil || !match {
		return nil, ErrPasswordVerification
	}

	session := NewSession(user.ID, time.Now().AddDate(0, 6, 0))

	host, _, _ := net.SplitHostPort(remoteAddr)
	row = db.Pool.QueryRow(context.Background(), "insert into sessions (user_id, expires_at, ip) values ($1, $2, $3) returning id", session.UserID, session.ExpiresAt, host)

	if err := row.Scan(&session.ID); err != nil {
		return nil, api.Error{StatusCode: 500, Message: err.Error(), Code: "internal_error"}
	}

	return session, nil
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
