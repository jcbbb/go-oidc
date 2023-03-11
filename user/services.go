package user

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jcbbb/go-oidc/api"
	"github.com/jcbbb/go-oidc/argon"
	"github.com/jcbbb/go-oidc/db"
)

var (
	ErrUserNotFound         = api.Error{StatusCode: http.StatusNotFound, Message: "User not found", Code: "resource_not_found"}
	ErrPasswordVerification = api.Error{StatusCode: http.StatusBadRequest, Message: "Password verification failed", Code: "bad_request"}
	ErrJSONParse            = api.Error{StatusCode: http.StatusUnprocessableEntity, Message: "Unable to parse JSON body", Code: "unprocessable_entity"}
)

func New(firstName, lastName, email, phone, password, picture string) *User {
	h := md5.New()
	io.WriteString(h, email)
	hex := hex.EncodeToString(h.Sum(nil))
	picture = "https://gravatar.com/avatar/" + hex + "?d=retro"

	return &User{
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
		Phone:     phone,
		Password:  password,
		Picture:   picture,
	}
}

func NewSession(userId uint, expiresAt time.Time) *Session {
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

func (user *User) VerifyPassword(password string) error {
	valid, err := argon.Verify(password, user.Password)
	if err != nil || !valid {
		return ErrPasswordVerification
	}
	return nil
}

func GetByEmail(email string) (*User, error) {
	var user User
	row := db.Pool.QueryRow(context.Background(), "select id, password from users where email = $1", email)

	if err := row.Scan(&user.ID, &user.Password); err != nil {
		return nil, api.ErrInternal("internal error", "")
	}

	return &user, nil
}

func GetByPhone(phone string) (*User, error) {
	var user User
	row := db.Pool.QueryRow(context.Background(), "select id, password from users where phone = $1", phone)

	if err := row.Scan(&user.ID, &user.Password); err != nil {
		return nil, api.ErrInternal("internal error", "")
	}

	return &user, nil
}

func getAll() (*[]User, error) {
	var users []User
	rows, err := db.Pool.Query(context.Background(), "select id, first_name, last_name, email, phone from users order by id desc")

	defer rows.Close()

	if err != nil {
		fmt.Println(err)
		return nil, api.Error{StatusCode: 500, Message: "Something went wrong", Code: "query_err"}
	}

	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Phone); err != nil {
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

func Create(req NewUserReq) (*User, error) {
	user := New(req.FirstName, req.LastName, req.Email, req.Phone, req.Password, req.Picture)
	err := user.hashPassword()

	if err != nil {
		return nil, api.ErrInternal("Unable to hash password", "")
	}

	row := db.Pool.QueryRow(
		context.Background(),
		"insert into users (first_name, last_name, email, phone, password, picture) values ($1, $2, nullif($3, ''), nullif($4, ''), $5, $6) returning id",
		user.FirstName, user.LastName, user.Email, user.Phone, user.Password, user.Picture,
	)

	if err := row.Scan(&user.ID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgerrcode.IsIntegrityConstraintViolation(pgErr.Code) {
				return nil, api.ErrConflict("User already exists", "")
			}
		}
		return nil, api.ErrInternal("Something went wrong", "")
	}

	return user, nil
}

func GetById(userId uint) (*User, error) {
	var user User

	row := db.Pool.QueryRow(context.Background(), "select id, coalesce(email, '') as email, coalesce(phone, '') as phone, first_name, last_name, email_verified, phone_verified, verified from users where id = $1", userId)

	if err := row.Scan(&user.ID, &user.Email, &user.Phone, &user.FirstName, &user.LastName, &user.EmailVerified, &user.PhoneVerified, &user.Verified); err != nil {
		fmt.Println(err)
		return nil, api.Error{StatusCode: 500, Message: "Internal error", Code: "internal_error"}
	}

	return &user, nil
}

func GetByIds(ids []uint) ([]User, error) {
	var users []User

	rows, err := db.Pool.Query(context.Background(), "select id, coalesce(email, '') as email, coalesce(phone, '') as phone, first_name, last_name, email_verified, phone_verified, verified, picture from users where id = any($1)", ids)

	if err != nil {
		return nil, api.Error{StatusCode: 500, Message: err.Error(), Code: "query_err"}
	}

	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Email, &user.Phone, &user.FirstName, &user.LastName, &user.EmailVerified, &user.PhoneVerified, &user.Verified, &user.Picture); err != nil {
			return nil, api.Error{StatusCode: 500, Message: err.Error(), Code: "query_err"}
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, api.Error{StatusCode: 500, Message: err.Error(), Code: "query_err"}
	}

	return users, nil
}
