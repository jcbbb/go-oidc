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

func HandleLoginView(w http.ResponseWriter, r *http.Request) error {
	return views.Login.ExecuteTemplate(w, "login.html", "")
}

func HandleSignupView(w http.ResponseWriter, r *http.Request) error {
	return views.Signup.ExecuteTemplate(w, "signup.html", "")
}

func HandleAuthorizeView(w http.ResponseWriter, r *http.Request) error {
	// return views.Render(w, "authorize", "")
	return nil
}

func HandleSignup(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func HandleLogin(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func HandleCreate(w http.ResponseWriter, r *http.Request) error {
	var userReq NewUserReq
	defer r.Body.Close()

	err := json.NewDecoder(r.Body).Decode(&userReq)

	if err != nil {
		return ErrJSONParse
	}

	user, err := create(userReq)

	if err != nil {
		return err
	}

	return api.WriteJSON(w, http.StatusCreated, user)
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
