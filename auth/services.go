package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jcbbb/go-oidc/api"
	"github.com/jcbbb/go-oidc/client"
	"github.com/jcbbb/go-oidc/db"
	"github.com/jcbbb/go-oidc/securecookie"
	"github.com/jcbbb/go-oidc/util"
)

var (
	ErrMissingCodeChallenge    = api.Error{StatusCode: http.StatusBadRequest, Message: "Missing required parameter: code_challenge", Code: "invalid_request"}
	ErrMissingResponseType     = api.Error{StatusCode: http.StatusBadRequest, Message: "Missing required parameter: response_type", Code: "invalid_request"}
	ErrUnsupportedResponseType = api.Error{StatusCode: http.StatusBadRequest, Message: "Unsupported response type", Code: "unsupported_response_type"}
	ErrInvalidScope            = api.Error{StatusCode: http.StatusBadRequest, Message: "Invalid scope", Code: "invalid_request"}
	ErrInvalidResponseType     = api.Error{StatusCode: http.StatusBadRequest, Message: "Invalid response type", Code: "invalid_request"}
	ErrSessionNotFound         = api.Error{StatusCode: http.StatusNotFound, Message: "Session not found", Code: "not_found"}
	ErrMissingClientID         = api.Error{StatusCode: http.StatusBadRequest, Message: "Missing client id, include client_id", Code: "bad_request"}
	ErrMissingGrantType        = api.Error{StatusCode: http.StatusBadRequest, Message: "Missing grant type, include grant_type", Code: "bad_request"}
	ErrInvalidGrantType        = api.Error{StatusCode: http.StatusBadRequest, Message: "Invalid grant type, use one of following: authorization_code, password, client_credentials", Code: "bad_request"}
	ErrMissingPassword         = api.Error{StatusCode: http.StatusBadRequest, Message: "Missing password or username", Code: "bad_request"}
	ErrMissingAuthCode         = api.Error{StatusCode: http.StatusBadRequest, Message: "Missing auth code, include code", Code: "bad_request"}
	ErrMissingCodeVerifier     = api.Error{StatusCode: http.StatusBadRequest, Message: "Missing code verifier, include code_verifier", Code: "bad_request"}
	ErrMissingRedirectURI      = api.Error{StatusCode: http.StatusBadRequest, Message: "Missing redirect uri, include redirect_uri", Code: "bad_request"}
	ErrMissingClientSecret     = api.Error{StatusCode: http.StatusBadRequest, Message: "Missing client secret, include client_secret", Code: "bad_request"}
)

var (
	GrantTypePassword          = "password"
	GrantTypeAuthCode          = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
)

func NewSession(userId uint, expiresAt time.Time) *Session {
	return &Session{
		UserID:    userId,
		ExpiresAt: expiresAt,
		Active:    true,
	}
}

func isValidResponseType(rt string) bool {
	switch rt {
	case "code", "token":
		return true
	}
	return false
}

func isValidGrantType(gt string) bool {
	switch gt {
	case "authorization_code", "client_credentials", "password":
		return true
	}
	return false
}

func NewAuthorizationReq(client *client.Client, responseType, codeChallenge, state string) *AuthorizationReq {
	return &AuthorizationReq{
		Client:        client,
		ResponseType:  responseType,
		CodeChallenge: codeChallenge,
		State:         state,
	}
}

func (t *TokenReq) validate() error {
	if t.ClientID == "" {
		return ErrMissingClientID
	}

	if t.GrantType == "" {
		return ErrMissingGrantType
	}

	if !isValidGrantType(t.GrantType) {
		return ErrInvalidGrantType
	}

	if t.GrantType == GrantTypePassword {
		if t.Password == "" || t.Username == "" {
			return ErrMissingPassword
		}
	}

	if t.GrantType == GrantTypeAuthCode {
		if t.CodeVerifier == "" {
			return ErrMissingCodeVerifier
		}

		if t.Code == "" {
			return ErrMissingAuthCode
		}

		if t.RedirectURI == "" {
			return ErrMissingRedirectURI
		}
	}

	if t.GrantType == GrantTypeClientCredentials {
		if t.ClientSecret == "" {
			return ErrMissingClientSecret
		}
	}

	return nil
}

func (r *AuthorizationReq) setUserId(userId string) *AuthorizationReq {
	i, _ := strconv.Atoi(userId)
	r.UserID = uint(i)
	return r
}

func (r *AuthorizationReq) setCode() *AuthorizationReq {
	r.Code = util.RandN(6)
	return r
}

func (r *AuthorizationReq) setScope(scope string) *AuthorizationReq {
	if len(scope) == 0 {
		r.Scopes = r.Client.Scopes
	} else {
		scopes, err := getScopes(scope)
		if err != nil {
			r.Scopes = scopes
		}
	}

	return r
}

func (r *AuthorizationReq) setCodeChallengeMethod(method string) *AuthorizationReq {
	r.CodeChallengeMethod = method
	if len(r.CodeChallengeMethod) == 0 {
		r.CodeChallengeMethod = "S256"
	}

	return r
}

func (r *AuthorizationReq) setRedirectUri(uri string) *AuthorizationReq {
	r.RedirectURI = uri
	if len(r.RedirectURI) == 0 {
		r.RedirectURI = r.Client.RedirectURIs[0]
	}

	return r
}

func (r *AuthorizationReq) ScopeString() string {
	var sb strings.Builder

	for _, v := range r.Scopes {
		sb.WriteString(v.Key)
	}

	return sb.String()
}

func (r *AuthorizationReq) validate() (*AuthorizationReq, error) {
	if r.CodeChallenge == "" {
		return nil, ErrMissingCodeChallenge
	}

	if r.ResponseType == "" {
		return nil, ErrMissingResponseType
	}

	if !isValidResponseType(r.ResponseType) {
		return nil, ErrUnsupportedResponseType
	}

	clientScopes, err := client.GetScopes(r.Client.ID)
	if err != nil {
		return nil, err
	}

	for _, v := range r.Scopes {
		if util.Contains(clientScopes, func(s client.Scope) bool {
			return s.Key == v.Key
		}) {
			continue
		} else {
			return nil, ErrInvalidScope
		}
	}

	if !util.Contains(r.Client.ResponseTypes, func(s string) bool {
		return s == r.ResponseType
	}) {
		return nil, ErrInvalidResponseType
	}

	return r, nil
}

func (r *AuthorizationReq) save() (*AuthorizationReq, error) {
	err := db.Pool.QueryRow(context.Background(),
		"insert into authorization_requests (redirect_uri, response_type, client_id, code_challenge, code_challenge_method, scope, state, user_id, code)"+
			"values ($1, $2, $3, $4, $5, $6, $7, $8, $9) returning id",
		r.RedirectURI, r.ResponseType, r.Client.ID, r.CodeChallenge, r.CodeChallengeMethod, r.ScopeString(), r.State, r.UserID, r.Code,
	).Scan(&r.ID)

	if err != nil {
		return nil, err
	}

	return r, nil
}

func (r *AuthorizationReq) verifyCodeChallenge(verifier string) (bool, error) {
	b, err := base64.URLEncoding.DecodeString(verifier)
	if err != nil {
		return false, err
	}
	hash := sha256.New()
	hash.Write(b)
	chksm := base64.URLEncoding.EncodeToString(hash.Sum(nil))

	return chksm == r.CodeChallenge, nil
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
			return session, ErrSessionNotFound
		}

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

func createSession(userId uint, remoteAddr string) (*Session, error) {
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

func getScopes(scope string) ([]client.Scope, error) {
	scopesArr := strings.Split(scope, " ")
	var scopes []client.Scope

	rows, err := db.Pool.Query(context.Background(), "select key, coalesce(icon_uri, ''), description "+
		"from scopes s join scope_translations st on st.scope_id = s.id where s.id = any($1)", scopesArr)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var scope client.Scope
		if err := rows.Scan(&scope.Key, &scope.IconURI, &scope.Description); err != nil {
			return nil, err
		}

		scopes = append(scopes, scope)
	}

	return scopes, nil
}
