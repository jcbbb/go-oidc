package main

import (
	"context"
	"embed"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jcbbb/go-oidc/api"
	"github.com/jcbbb/go-oidc/db"
	"github.com/jcbbb/go-oidc/user"
	"github.com/jcbbb/go-oidc/views"
	"github.com/joho/godotenv"
)

// Client (application redirecting resource owner (user) to Authorization Server)
// Resource Owner (user)

/* Resource Server
 * Token introspection (checking token) - https://www.rfc-editor.org/rfc/rfc7662.html
 */
/* Authorization Server
 * metadata - https://www.rfc-editor.org/rfc/rfc8414.html
 * dynamic Client registration - https://www.rfc-editor.org/rfc/rfc7591.html
 * dynamic Client update - https://www.rfc-editor.org/rfc/rfc7592.html
 * jwt - https://www.rfc-editor.org/rfc/rfc9068.html
 */

// Authorization server MUST:
// - reject the request if redirect_uri doesn't exactly match one of the predefined redirect uris
// - include redirect_uri if multiple redirect_uris have been predefined
// - inform the Resouce Owner if redirect_uri is invalid and not redirect
// - link client_id with issued access/refresh tokens
// - have default scope or reject the request indicating missing scope param
// - include following in successful token response (access_token*, token_type*, expires_in(seconds)^, scope^, refresh_token?)
// - authenticate client, check redirect_uri and code grant when requesing for token
// - bind refresh token to the scope
// - set Cache-Control to no-store in responses containing sensitive data (tokens, credentials)
// - have following error format: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-07#name-error-response

/* Authorization Request */
// response_type*
// client_id*
// code_challenge^ - REQUIRED or RECOMMENDED
// code_challenge_method - S256 (required if code_challenge is present)
// redirect_uri?
// scope?
// state?

/* e.g. /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
   &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
   &code_challenge=6fdkQaPm51l13DSukcAH3Mdx7_ntecHYd1vi3n0hMZY
   &code_challenge_method=S256 */

/* Authorization Response */
// code* - used only once, max. 10-minute ttl, is bound to client_id, code_challenge and redirect_uri. If code is used more than once, revoke all tokens associated with the code.
// state - received from client
// iss - defined in Authorization Server metadata

/* Token Request */
// client_id*

// const sid = req.session.get("sid") || req.headers["authorization"];
// const session = await SessionService.get_one(sid);

// if (sid && !session) {
//   req.session.delete();
// }

// const user = await UserService.get_one(session?.user_id, ["roles"]);
// req.user = user?.toJSON();

// func AttachUser(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		cookie, err := r.Cookie("ssid")
// 		if err != nil {
// 			return
// 		}
// 		sid, err := securecookie.Decode(cookie)
// 		if err != nil {
// 			return
// 		}

// 		session, err := user.GetSession(sid)

// 		if err != nil {
// 			return
// 		}

// 		user, err := user.GetUser(session.UserID)

// 		if err != nil {
// 			return
// 		}

// 		fmt.Printf("%+v\n", user)
// 		next.ServeHTTP(w, r)
// 	})
// }

//go:embed views/*.html
var viewsFS embed.FS

func main() {
	err := godotenv.Load()

	if err != nil {
		panic(err)
	}

	postgresUri := os.Getenv("POSTGRES_URI")
	db.Pool, err = pgxpool.New(context.Background(), postgresUri)

	if err != nil {
		panic(err)
	}

	defer db.Pool.Close()

	views.ViewsFS = viewsFS
	views.LoadViews()

	r := chi.NewRouter()
	// r.Use(user.HandleResolveSessions)
	// r.Use(user.HandleAttach)
	// mux := NewMux()
	// api := NewApi(pool)

	// // mux.Post("/clients", makeHandlerFunc(createClient))                    // register clients (apps)
	// mux.Get("/authorize", func(w http.ResponseWriter, r *http.Request) {}) // authorization consent screen
	// mux.Post("/token", func(w http.ResponseWriter, r *http.Request) {})    // retrieve token

	r.Get("/users", api.MakeHandlerFuncJSON(user.HandleGetAll))
	r.Get("/auth/login", api.MakeHandlerFuncJSON(user.HandleLoginView))
	r.Get("/auth/signup", api.MakeHandlerFuncJSON(user.HandleSignupView))
	r.Post("/auth/signup", api.MakeHandlerFuncJSON(user.HandleLogin))
	r.Post("/auth/login", api.MakeHandlerFuncJSON(user.HandleSignup))
	r.Post("/users", api.MakeHandlerFunc(user.HandleCreate))
	r.Get("/users/new", api.MakeHandlerFunc(user.HandleSignupView))
	r.Get("/sessions/new", api.MakeHandlerFunc(user.HandleLoginView))
	r.Post("/sessions", api.MakeHandlerFunc(user.HandleLogin))

	workDir, _ := os.Getwd()
	FileServer(r, "/static", http.Dir(filepath.Join(workDir, "static")))
	log.Fatal(http.ListenAndServe(":3000", r))
}

func FileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit any URL parameters.")
	}

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", 301).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))
		fs.ServeHTTP(w, r)
	})
}
