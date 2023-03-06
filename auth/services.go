package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jcbbb/go-oidc/api"
	"github.com/jcbbb/go-oidc/db"
	"github.com/jcbbb/go-oidc/securecookie"
	"github.com/jcbbb/go-oidc/util"
)

func NewSession(userId int, expiresAt time.Time) *Session {
	return &Session{
		UserID:    userId,
		ExpiresAt: expiresAt,
		Active:    true,
	}
}

func isValidResponseType(rt oauthResponseType) bool {
	switch rt {
	case CodeResponseType, TokenResponseType:
		return true
	}
	return false
}

func (r *AuthorizationReq) valid() (bool, error) {
	if r.ClientID == "" {
		return false, api.Error{Code: "invalid_request", Message: "Missing required parameter: client_id", StatusCode: http.StatusBadRequest}
	}

	if r.CodeChallenge == "" {
		return false, api.Error{Code: "invalid_request", Message: "Missing required parameter: code_challenge", StatusCode: http.StatusBadRequest}
	}

	if r.ResponseType == "" {
		return false, api.Error{Code: "invalid_request", Message: "Missing required parameter: response_type", StatusCode: http.StatusBadRequest}
	}

	if !isValidResponseType(r.ResponseType) {
		return false, api.Error{Code: "unsupported_response_type", Message: "Unsupported response type", StatusCode: http.StatusBadRequest}
	}

	return true, nil
}

func decodeCookies(r *http.Request) (sid string, sids []string, err error) {
	sidCookie, _ := r.Cookie(securecookie.SidCookieName)
	if sidCookie == nil {
		sidCookie = &http.Cookie{}
	}
	sidsCookie, _ := r.Cookie(securecookie.SidsCookieName)
	if sidsCookie == nil {
		sidsCookie = &http.Cookie{}
	}

	sid, err = securecookie.Decode(sidCookie)
	if err != nil {
		return "", nil, err
	}

	sidsStr, err := securecookie.Decode(sidsCookie)
	if err != nil {
		return "", nil, err
	}

	sids = strings.Split(sidsStr, "|")

	return sid, sids, nil
}

func getSession(sid string) (Session, error) {
	var session Session
	row := db.Pool.QueryRow(context.Background(), "select id, user_id, expires_at, active from sessions where id = $1", sid)

	if err := row.Scan(&session.ID, &session.UserID, &session.ExpiresAt, &session.Active); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return session, api.ErrResourceNotFound("Session not found for user", "")
		}

		fmt.Printf("After")
		return session, api.ErrInternal("Internal error", "")
	}

	return session, nil
}

func getSessions(sids []string) ([]Session, error) {
	var sessions []Session
	rows, err := db.Pool.Query(context.Background(), "select id, user_id, expires_at, active from sessions where id = any($1)", sids)

	defer rows.Close()
	if err != nil {
		fmt.Println(err)
		return nil, api.Error{StatusCode: 500, Message: "Something went wrong", Code: "query_err"}
	}

	for rows.Next() {
		var session Session
		if err := rows.Scan(&session.ID, &session.UserID, &session.ExpiresAt, &session.Active); err != nil {
			fmt.Println(err)
			return nil, api.Error{StatusCode: 500, Message: "Something went wrong", Code: "query_err"}
		}
		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		fmt.Println(err)
		return nil, api.Error{StatusCode: 500, Message: "Something went wrong", Code: "query_err"}
	}

	return sessions, nil
}

func createSession(userId int, remoteAddr string) (*Session, error) {
	session := NewSession(userId, time.Now().AddDate(0, 6, 0))
	host, _, _ := net.SplitHostPort(remoteAddr)

	row := db.Pool.QueryRow(context.Background(), "insert into sessions (user_id, expires_at, ip) values ($1, $2, $3) returning id", session.UserID, session.ExpiresAt, host)

	if err := row.Scan(&session.ID); err != nil {
		return nil, api.ErrInternal(err.Error(), "")
	}

	return session, nil
}

func updateSessionCookies(w http.ResponseWriter, r *http.Request, session *Session) error {
	sidsCookie, err := r.Cookie(securecookie.SidsCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		sidsCookie = &http.Cookie{}
	}

	sids, err := securecookie.Decode(sidsCookie)

	if err != nil {
		return api.Error{StatusCode: 500, Message: err.Error(), Code: "internal_error"}
	}

	cleanSids := util.Filter(strings.Split(sids, "|"), func(s string) bool { return len(s) != 0 })
	sids = strings.Join(append(cleanSids, session.ID), "|")
	value, err := securecookie.Encode(securecookie.SidsCookieName, sids)

	if err != nil {
		return api.Error{StatusCode: 500, Message: err.Error(), Code: "internal_error"}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     securecookie.SidsCookieName,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Value:    value,
	})

	value, err = securecookie.Encode(securecookie.SidCookieName, session.ID)

	if err != nil {
		return api.Error{StatusCode: 500, Message: err.Error(), Code: "internal_error"}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     securecookie.SidCookieName,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Value:    value,
		Expires:  session.ExpiresAt,
	})

	return nil
}
