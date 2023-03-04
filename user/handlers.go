package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jcbbb/go-oidc/api"
	"github.com/jcbbb/go-oidc/securecookie"
	"github.com/jcbbb/go-oidc/util"
	"github.com/jcbbb/go-oidc/views"
)

func HandleResolveSessions(next http.Handler) http.Handler {
	return api.MakeHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		sidCookie, _ := r.Cookie(securecookie.SidCookieName)
		if sidCookie == nil {
			sidCookie = &http.Cookie{}
		}
		sidsCookie, _ := r.Cookie(securecookie.SidsCookieName)
		if sidsCookie == nil {
			sidsCookie = &http.Cookie{}
		}

		sid, err := securecookie.Decode(sidCookie)
		if err != nil {
			return err
		}

		session, err := getSession(sid)
		if err != nil {
			return err
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

		fmt.Printf("%+v\n", session)
		fmt.Printf("%+v\n", sessions)

		next.ServeHTTP(w, r)
		return nil
	})
}

func HandleAttach(next http.Handler) http.Handler {
	return api.MakeHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		sidCookie, _ := r.Cookie(securecookie.SidCookieName)
		if sidCookie == nil {
			sidCookie = &http.Cookie{}
		}

		sid, err := securecookie.Decode(sidCookie)
		if err != nil {
			return err
		}

		session, err := getSession(sid)
		if err != nil {
			return err
		}

		fmt.Printf("SESSION: %+v\n", session)

		user, err := getUser(session.UserID)
		if err != nil {
			return err
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
		return nil
	})
}

func HandleGetAll(w http.ResponseWriter, r *http.Request) error {
	// user := r.Context().Value("user").(*User)

	users, err := getAll()

	if err != nil {
		return err
	}

	return api.WriteJSON(w, http.StatusOK, users)
}

type LoginViewParams struct {
	Method string
	Flash  *util.FlashMessage
}

type SignupParams struct {
	Method string
	Flash  *util.FlashMessage
}

func HandleLoginView(w http.ResponseWriter, r *http.Request) error {
	method := r.URL.Query().Get("method")

	fm, err := util.GetFlash(w, r)
	if err != nil {
		return err
	}

	params := &LoginViewParams{
		Method: method,
		Flash:  fm,
	}

	return views.Login.ExecuteTemplate(w, "login.html", params)
}

func HandleSignupView(w http.ResponseWriter, r *http.Request) error {
	method := r.URL.Query().Get("method")
	fm, err := util.GetFlash(w, r)
	if err != nil {
		return err
	}

	params := &SignupParams{
		Method: method,
		Flash:  fm,
	}

	return views.Signup.ExecuteTemplate(w, "signup.html", params)
}

func HandleAuthorizeView(w http.ResponseWriter, r *http.Request) error {
	// return views.Render(w, "authorize", "")
	return nil
}

func HandleSignup(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func HandleLogin(w http.ResponseWriter, r *http.Request) error {
	req := SessionReq{
		Email:    r.FormValue("email"),
		Phone:    r.FormValue("phone"),
		Password: r.FormValue("password"),
	}

	var user *User
	var err error

	if len(req.Email) > 0 {
		user, err = getByEmail(req.Email)
	} else {
		user, err = getByPhone(req.Phone)
	}

	if err != nil {
		return err
	}

	err = user.verifyPassword(req.Password)
	if err != nil {
		return err
	}

	session, err := insertSession(user.ID, r.RemoteAddr)

	if err := updateSessionCookies(w, r, session); err != nil {
		return err
	}

	returnTo := r.URL.Query().Get("return_to")
	if len(returnTo) == 0 {
		returnTo = "/"
	}

	http.Redirect(w, r, returnTo, http.StatusFound)
	return nil
}

func HandleCreate(w http.ResponseWriter, r *http.Request) error {
	userReq := NewUserReq{
		Email:     r.FormValue("email"),
		Phone:     r.FormValue("phone"),
		Password:  r.FormValue("password"),
		FirstName: r.FormValue("first_name"),
		LastName:  r.FormValue("last_name"),
	}

	user, err := create(userReq)

	if err != nil {
		return err
	}

	session, err := insertSession(user.ID, r.RemoteAddr)

	if err != nil {
		return err
	}

	if err = updateSessionCookies(w, r, session); err != nil {
		return err
	}

	returnTo := r.URL.Query().Get("return_to")
	if len(returnTo) == 0 {
		returnTo = "/"
	}

	http.Redirect(w, r, returnTo, http.StatusFound)
	return nil
}

func HandleCreateSession(w http.ResponseWriter, r *http.Request) error {
	var sessionReq SessionReq
	defer r.Body.Close()

	err := json.NewDecoder(r.Body).Decode(&sessionReq)

	if err != nil {
		return ErrJSONParse
	}

	session, err := createSession(sessionReq, r.RemoteAddr)

	if err != nil {
		return api.Error{StatusCode: 500, Message: err.Error(), Code: "internal_error"}
	}

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
	})

	return api.WriteJSON(w, http.StatusOK, session)
}
