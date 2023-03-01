package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jcbbb/go-oidc/api"
	"github.com/jcbbb/go-oidc/securecookie"
	"github.com/jcbbb/go-oidc/util"
)

func HandleAttach(next http.Handler) http.Handler {
	return api.MakeHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		cookie, err := r.Cookie(securecookie.SidCookieName)
		if err != nil {
			return err
		}

		sid, err := securecookie.Decode(cookie)
		if err != nil {
			return err
		}

		session, err := getSession(sid)

		if err != nil {
			return err
		}

		user, err := getUser(session.UserID)

		if err != nil {
			return err
		}

		fmt.Printf("%+v\n", user)
		next.ServeHTTP(w, r)
		return nil
	})
}

func HandleGetAll(w http.ResponseWriter, r *http.Request) error {
	users, err := getAll()

	if err != nil {
		return err
	}

	return api.WriteJSON(w, http.StatusOK, users)
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
