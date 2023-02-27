package user

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jcbbb/go-oidc/api"
	"github.com/jcbbb/go-oidc/argon"
	"github.com/jcbbb/go-oidc/db"
)

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

type UserLoginReq struct {
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

func CreateUser(w http.ResponseWriter, r *http.Request) error {
	var userReq NewUserReq
	defer r.Body.Close()

	err := json.NewDecoder(r.Body).Decode(&userReq)

	if err != nil {
		return api.Error{StatusCode: 500, Message: "Unable to decode json body", Code: "invalid_json_body"}
	}

	hash, err := argon.Hash(userReq.Password)

	if err != nil {
		return api.Error{StatusCode: 500, Message: "Unable to hash password", Code: "invalid_hash"}
	}

	row := db.Pool.QueryRow(
		context.Background(),
		"insert into users (first_name, last_name, email, phone, password) values ($1, $2, $3, $4, $5) returning id",
		userReq.FirstName, userReq.LastName, userReq.Email, userReq.Phone, hash,
	)

	if err := row.Scan(&userReq.ID); err != nil {
		fmt.Println(err)
	}

	user := New(userReq.FirstName, userReq.LastName, userReq.Email, userReq.Phone, userReq.Password)

	return api.WriteJSON(w, http.StatusCreated, user)
}

func CreateSession(w http.ResponseWriter, r *http.Request) error {
	var loginReq UserLoginReq
	defer r.Body.Close()

	err := json.NewDecoder(r.Body).Decode(&loginReq)

	if err != nil {
		return api.Error{StatusCode: 400, Message: "Unable to decode json body", Code: "invalid_json"}
	}

	var user User

	row := db.Pool.QueryRow(context.Background(), "select password, email from users where email = $1", loginReq.Email)

	if err := row.Scan(&user.Password, &user.Email); err != nil {
		fmt.Println(err)
		if err == sql.ErrNoRows {
			return api.Error{StatusCode: 404, Message: "User not found", Code: "resource_not_found"}
		}
		return api.Error{StatusCode: 500, Message: "Internal error", Code: "internal_error"}
	}

	match, err := user.verifyPassword(loginReq.Password)

	if err != nil {
		fmt.Println(err)
		return api.Error{StatusCode: 500, Message: err.Error(), Code: "internal_error"}
	}

	return api.WriteJSON(w, http.StatusOK, match)
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
