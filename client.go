package main

func NewClient(id, name, secret, uri, scope, logoUri, tosUri, policyUri, tokenEndpointAuthMethod string, redirectUris, contacts, grantTypes, responseTypes []string) *Client {
	return &Client{
		ID:                      id,
		RedirectURIs:            redirectUris,
		Name:                    name,
		Secret:                  secret,
		URI:                     uri,
		Scope:                   scope,
		Contacts:                contacts,
		LogoURI:                 logoUri,
		TosURI:                  tosUri,
		PolicyURI:               policyUri,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
	}
}
