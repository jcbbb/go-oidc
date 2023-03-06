package auth

import (
	"net/http"
	"strings"

	"github.com/jcbbb/go-oidc/securecookie"
	"github.com/jcbbb/go-oidc/user"
	"github.com/jcbbb/go-oidc/util"
	"github.com/jcbbb/go-oidc/views"
)

func HandleConsentView(w http.ResponseWriter, r *http.Request) error {
	req := AuthorizationReq{
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
		ResponseType:        oauthResponseType(r.URL.Query().Get("response_type")),
	}

	if _, err := req.valid(); err != nil {
		return views.Error.ExecuteTemplate(w, "error.html", err)
	}

	sidsCookie, _ := r.Cookie(securecookie.SidsCookieName)
	if sidsCookie == nil {
		sidsCookie = &http.Cookie{}

	}

	sidsStr, err := securecookie.Decode(sidsCookie)
	if err != nil {
		return err
	}

	sids := strings.Split(sidsStr, "|")
	sessions, err := getSessions(sids)

	if err != nil {
		return err
	}

	userIds := make([]int, len(sessions))
	for _, v := range sessions {
		userIds = append(userIds, v.UserID)
	}

	users, err := user.GetByIds(userIds)
	if err != nil {
		return err
	}

	params := struct {
		Users []user.User
	}{users}

	return views.Consent.ExecuteTemplate(w, "consent.html", params)
}
func HandleLoginView(w http.ResponseWriter, r *http.Request) error {
	method := r.URL.Query().Get("method")

	fm, err := util.GetFlash(w, r)
	if err != nil {
		return err
	}

	params := struct {
		Method string
		Flash  *util.FlashMessage
	}{method, fm}

	return views.Login.ExecuteTemplate(w, "login.html", params)
}

func HandleSignupView(w http.ResponseWriter, r *http.Request) error {
	method := r.URL.Query().Get("method")
	fm, err := util.GetFlash(w, r)
	if err != nil {
		return err
	}

	params := struct {
		Method string
		Flash  *util.FlashMessage
	}{method, fm}

	return views.Signup.ExecuteTemplate(w, "signup.html", params)
}

func HandleLogin(w http.ResponseWriter, r *http.Request) error {
	req := LoginReq{
		Email:    r.FormValue("email"),
		Phone:    r.FormValue("phone"),
		Password: r.FormValue("password"),
	}

	var u *user.User
	var err error

	if len(req.Email) > 0 {
		u, err = user.GetByEmail(req.Email)
	} else {
		u, err = user.GetByPhone(req.Phone)
	}

	if err != nil {
		return err
	}

	err = u.VerifyPassword(req.Password)

	if err != nil {
		return err
	}

	session, err := createSession(u.ID, r.RemoteAddr)

	if err != nil {
		return err
	}

	if err = updateSessionCookies(w, r, session); err != nil {
		return err
	}

	redirectUri := r.URL.Query().Get("redirect_uri")
	if len(redirectUri) == 0 {
		redirectUri = "/"
	}

	http.Redirect(w, r, redirectUri, http.StatusFound)
	return nil
}

func HandleSignup(w http.ResponseWriter, r *http.Request) error {
	req := user.NewUserReq{
		Email:     r.FormValue("email"),
		Phone:     r.FormValue("phone"),
		Password:  r.FormValue("password"),
		FirstName: r.FormValue("first_name"),
		LastName:  r.FormValue("last_name"),
	}

	user, err := user.Create(req)

	if err != nil {
		return err
	}

	session, err := createSession(user.ID, r.RemoteAddr)

	if err = updateSessionCookies(w, r, session); err != nil {
		return err
	}

	redirectUri := r.URL.Query().Get("redirect_uri")
	if len(redirectUri) == 0 {
		redirectUri = "/"
	}

	http.Redirect(w, r, redirectUri, http.StatusFound)
	return nil
}
