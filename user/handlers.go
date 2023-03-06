package user

import (
	"net/http"

	"github.com/jcbbb/go-oidc/api"
)

// func HandleResolveSessions(next http.Handler) http.Handler {
// 	return api.MakeHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
// 		sidCookie, _ := r.Cookie(securecookie.SidCookieName)
// 		if sidCookie == nil {
// 			sidCookie = &http.Cookie{}
// 		}
// 		sidsCookie, _ := r.Cookie(securecookie.SidsCookieName)
// 		if sidsCookie == nil {
// 			sidsCookie = &http.Cookie{}
// 		}

// 		sid, err := securecookie.Decode(sidCookie)
// 		if err != nil {
// 			return err
// 		}

// 		session, err := getSession(sid)
// 		if err != nil {
// 			return err
// 		}

// 		sidsStr, err := securecookie.Decode(sidsCookie)
// 		if err != nil {
// 			return err
// 		}

// 		sids := strings.Split(sidsStr, "|")
// 		sessions, err := getSessions(sids)

// 		if err != nil {
// 			return err
// 		}

// 		fmt.Printf("%+v\n", session)
// 		fmt.Printf("%+v\n", sessions)

// 		next.ServeHTTP(w, r)
// 		return nil
// 	})
// }

// func HandleAttach(next http.Handler) http.Handler {
// 	return api.MakeHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
// 		sidCookie, _ := r.Cookie(securecookie.SidCookieName)
// 		if sidCookie == nil {
// 			sidCookie = &http.Cookie{}
// 		}

// 		sid, err := securecookie.Decode(sidCookie)
// 		if err != nil {
// 			return err
// 		}

// 		session, err := getSession(sid)
// 		if err != nil {
// 			return err
// 		}

// 		fmt.Printf("SESSION: %+v\n", session)

// 		user, err := getUser(session.UserID)
// 		if err != nil {
// 			return err
// 		}

// 		ctx := r.Context()
// 		ctx = context.WithValue(ctx, "user", user)
// 		next.ServeHTTP(w, r.WithContext(ctx))
// 		return nil
// 	})
// }

func HandleGetAll(w http.ResponseWriter, r *http.Request) error {
	// user := r.Context().Value("user").(*User)

	users, err := getAll()

	if err != nil {
		return err
	}

	return api.WriteJSON(w, http.StatusOK, users)
}

// func HandleConsentView(w http.ResponseWriter, r *http.Request) error {
// 	sidsCookie, _ := r.Cookie(securecookie.SidsCookieName)
// 	if sidsCookie == nil {
// 		sidsCookie = &http.Cookie{}

// 	}

// 	sidsStr, err := securecookie.Decode(sidsCookie)
// 	if err != nil {
// 		return err
// 	}

// 	sids := strings.Split(sidsStr, "|")
// 	sessions, err := getSessions(sids)

// 	if err != nil {
// 		return err
// 	}

// 	userIds := make([]int, len(sessions))
// 	for _, v := range sessions {
// 		userIds = append(userIds, v.UserID)
// 	}

// 	users, err := getUsersById(userIds)
// 	if err != nil {
// 		return err
// 	}

// 	params := ConsentParams{
// 		Users: users,
// 	}
// 	return views.Consent.ExecuteTemplate(w, "consent.html", params)
// }
