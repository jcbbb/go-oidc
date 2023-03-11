package client

type Scope struct {
	IconURI     string
	Key         string
	Description string
}

type Client struct {
	ID                      string
	Name                    string
	URI                     string
	Scope                   string
	Scopes                  []Scope
	LogoURI                 string
	TosURI                  string
	PolicyURI               string
	RedirectURIs            []string
	Contacts                []string
	GrantTypes              []string
	ResponseTypes           []string
	TokenEndpointAuthMethod string
	secret                  string
}
