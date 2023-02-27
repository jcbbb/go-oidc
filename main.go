package main

import (
	"context"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jcbbb/go-oidc/api"
	"github.com/jcbbb/go-oidc/db"
	"github.com/jcbbb/go-oidc/user"
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

func main() {
	var err error
	db.Pool, err = pgxpool.New(context.Background(), "postgresql://jcbbb:2157132aA*codes@localhost:5432/oidc-dev")
	if err != nil {
		panic(err)
	}

	defer db.Pool.Close()

	r := chi.NewRouter()
	// mux := NewMux()
	// api := NewApi(pool)

	// // mux.Post("/clients", makeHandlerFunc(createClient))                    // register clients (apps)
	// mux.Get("/authorize", func(w http.ResponseWriter, r *http.Request) {}) // authorization consent screen
	// mux.Post("/token", func(w http.ResponseWriter, r *http.Request) {})    // retrieve token
	r.Get("/users", api.MakeHandlerFunc(user.GetAll))
	r.Post("/users", api.MakeHandlerFunc(user.CreateUser))
	r.Post("/sessions", api.MakeHandlerFunc(user.CreateSession))

	log.Fatal(http.ListenAndServe(":3000", r))
}
