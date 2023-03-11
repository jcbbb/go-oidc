package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jcbbb/go-oidc/api"
	"github.com/jcbbb/go-oidc/client"
	"github.com/jcbbb/go-oidc/securecookie"
	"github.com/jcbbb/go-oidc/user"
	"github.com/jcbbb/go-oidc/util"
	"github.com/jcbbb/go-oidc/views"
)

var (
	ErrInvalidClientSecret = api.Error{StatusCode: http.StatusUnauthorized, Message: "Invalid client or secret", Code: "unauthenticated"}
)

func HandleConsent(w http.ResponseWriter, r *http.Request) error {
	var (
		clientId            = r.URL.Query().Get("client_id")
		redirectUri         = r.URL.Query().Get("redirect_uri")
		scope               = r.URL.Query().Get("scope")
		state               = r.URL.Query().Get("state")
		codeChallenge       = r.URL.Query().Get("code_challenge")
		codeChallengeMethod = r.URL.Query().Get("code_challenge_method")
		responseType        = r.URL.Query().Get("response_type")
		userId              = r.FormValue("user_id")
	)

	c, err := client.GetById(clientId)

	if err != nil {
		return err
	}

	req, err := NewAuthorizationReq(c, responseType, codeChallenge, state).setScope(scope).setRedirectUri(redirectUri).setUserId(userId).setCodeChallengeMethod(codeChallengeMethod).setCode().validate()

	if err != nil {
		return err
	}

	req, err = req.save()
	if err != nil {
		return err
	}

	http.Redirect(w, r, req.RedirectURI+"?code="+req.Code+"&state="+req.State, http.StatusFound)
	return nil
}

func HandleToken(w http.ResponseWriter, r *http.Request) error {
	var tokenReq TokenReq

	defer r.Body.Close()
	err := json.NewDecoder(r.Body).Decode(&tokenReq)

	if err != nil {
		return err
	}

	if err := tokenReq.validate(); err != nil {
		return err
	}

	fmt.Printf("TOKEN REQUEST: %+v\n", tokenReq)
	return nil
}

func HandleClientCtx(next http.Handler) http.Handler {
	return api.MakeHandlerFuncJSON(func(w http.ResponseWriter, r *http.Request) error {
		authHeader := r.Header.Get("Authorization")
		parts := strings.Split(authHeader, " ")

		b, err := base64.RawStdEncoding.DecodeString(parts[1])

		if err != nil {
			return err
		}

		parts = strings.Split(string(b), ":")

		clientId := parts[0]
		clientSecret := parts[1]
		client, err := client.GetById(clientId)

		if err != nil {
			return err
		}

		valid := client.VerifySecret(clientSecret)

		if !valid {
			return ErrInvalidClientSecret
		}

		next.ServeHTTP(w, r)
		return nil
	})
}

// var b = make([]byte, 32)

func HandleConsentView(w http.ResponseWriter, r *http.Request) error {
	// rand.Read(b)
	// h := sha256.New()
	// h.Write(b)
	// bs := base64.URLEncoding.EncodeToString(h.Sum(nil))
	// verifier := base64.URLEncoding.EncodeToString(b)
	// fmt.Printf("CODE CHALLENGE %+v\n", bs)
	// fmt.Printf("VERIFIER %+v\n", verifier)
	// d, _ := base64.URLEncoding.DecodeString(verifier)
	// m := sha256.New()
	// m.Write(d)
	// fmt.Printf("BACK %+v\n", base64.URLEncoding.EncodeToString(m.Sum(nil)))

	var (
		clientId            = r.URL.Query().Get("client_id")
		redirectUri         = r.URL.Query().Get("redirect_uri")
		scope               = r.URL.Query().Get("scope")
		state               = r.URL.Query().Get("state")
		codeChallenge       = r.URL.Query().Get("code_challenge")
		codeChallengeMethod = r.URL.Query().Get("code_challenge_method")
		responseType        = r.URL.Query().Get("response_type")
	)

	c, err := client.GetById(clientId)

	if err != nil {
		return views.Error.ExecuteTemplate(w, "error.html", err)
	}

	req, err := NewAuthorizationReq(c, responseType, codeChallenge, state).
		setScope(scope).
		setRedirectUri(redirectUri).
		setCodeChallengeMethod(codeChallengeMethod).
		validate()

	if err != nil {
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

	userIds := make([]uint, len(sessions))
	for _, v := range sessions {
		userIds = append(userIds, v.UserID)
	}

	users, err := user.GetByIds(userIds)
	if err != nil {
		return err
	}

	fm, err := util.GetFlash(w, r)
	if err != nil {
		return err
	}

	params := struct {
		Users  []user.User
		Req    *AuthorizationReq
		Client *client.Client
		Action *url.URL
		Flash  *util.FlashMessage
	}{users, req, c, r.URL, fm}

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
