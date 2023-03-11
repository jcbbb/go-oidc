package client

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jcbbb/go-oidc/api"
	"github.com/jcbbb/go-oidc/db"
)

// func (c *Client) Validate(req auth.AuthorizationReq) (bool, error) {
// 	reqScope := strings.Split(req.Scope, " ")
// 	clientScope := strings.Split(c.Scope, " ")

// 	for _, v := range reqScope {
// 		if util.Contains(clientScope, v) {
// 			continue
// 		} else {
// 			return false, api.Error{Code: "invalid_request", Message: "Invalid scope", StatusCode: 400}
// 		}
// 	}
// 	if !util.Contains(c.ResponseTypes, req.ResponseType) {

// 	}

// 	return true, nil
// }

func (c *Client) VerifySecret(secret string) bool {
	return c.secret == secret
}

func (c *Client) ScopeString() string {
	var sb strings.Builder

	for _, v := range c.Scopes {
		sb.WriteString(v.Key)
	}

	return sb.String()
}

func (c *Client) RedirectURI() string {
	return c.RedirectURIs[0]
}

func GetScopes(clientId string) ([]Scope, error) {
	var scopes []Scope

	rows, err := db.Pool.Query(context.Background(), "select key, coalesce(icon_uri, ''), description "+
		"from client_scopes cs join scopes s on s.id = cs.scope_id join scope_translations st on st.scope_id = cs.scope_id where cs.client_id = $1", clientId)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var scope Scope
		if err := rows.Scan(&scope.Key, &scope.IconURI, &scope.Description); err != nil {
			return nil, err
		}

		scopes = append(scopes, scope)
	}

	return scopes, nil
}

func GetById(id string) (*Client, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, api.Error{Code: "invalid_request", Message: "Invalid uuid", StatusCode: 400}
	}

	var client Client

	row := db.Pool.QueryRow(context.Background(),
		"select id, name, secret, uri, logo_uri, tos_uri, policy_uri, redirect_uris, contacts, token_endpoint_auth_method, grant_types, response_types from clients where id = $1", id)

	if err := row.Scan(
		&client.ID,
		&client.Name,
		&client.secret,
		&client.URI,
		&client.LogoURI,
		&client.TosURI,
		&client.PolicyURI,
		&client.RedirectURIs,
		&client.Contacts,
		&client.TokenEndpointAuthMethod,
		&client.GrantTypes,
		&client.ResponseTypes,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, api.Error{Message: "Client not found", StatusCode: 401, Code: "invalid_client"}
		}
		return nil, api.ErrInternal("Internal error", "")
	}

	// rows, err := db.Pool.Query(context.Background(), "select key, coalesce(icon_uri, ''), description "+
	// 	"from client_scopes cs join scopes s on s.id = cs.scope_id join scope_translations st on st.scope_id = cs.scope_id where cs.client_id = $1", client.ID)

	// // TODO: HANDLE ERRORS PROPERLY
	// if err != nil {
	// 	return nil, err
	// }

	// defer rows.Close()

	// // TODO: HANDLE ERRORS PROPERLY
	// for rows.Next() {
	// 	var scope Scope
	// 	if err := rows.Scan(&scope.Key, &scope.IconURI, &scope.Description); err != nil {
	// 		return nil, err
	// 	}

	// 	client.Scopes = append(client.Scopes, scope)
	// }

	return &client, nil
}
