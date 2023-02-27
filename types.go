package main

type Client struct {
	ID                      string   `json:"id"`
	RedirectURIs            []string `json:"redirect_uris"`
	Name                    string   `json:"name"`
	Secret                  string   `json:"secret"`
	URI                     string   `json:"uri"`
	Scope                   string   `json:"scope"`
	Contacts                []string `json:"contacts"`
	LogoURI                 string   `json:"logo_uri"`
	TosURI                  string   `json:"tos_uri"`
	PolicyURI               string   `json:"policy_uri"`
	GrantTypes              []string `json:"grant_types"`                // authorization_code, implicit, password, client_credentials, refresh_token
	ResponseTypes           []string `json:"response_types"`             // code, token
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"` // none, client_secret_post, client_secret_basic
}
