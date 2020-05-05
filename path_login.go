package jwtauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type groupClaims struct {
	Groups []group `json:"groups"`
}

type group struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func pathLogin(b *jwtAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `login$`,
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "The role to log in against.",
			},
			"jwt": {
				Type:        framework.TypeString,
				Description: "The signed JWT to validate.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathLogin,
				Summary:  pathLoginHelpSyn,
			},
			logical.AliasLookaheadOperation: &framework.PathOperation{
				Callback: b.pathLogin,
			},
		},

		HelpSynopsis:    pathLoginHelpSyn,
		HelpDescription: pathLoginHelpDesc,
	}
}

func (b *jwtAuthBackend) pathLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}
	provider, err := b.getProvider(config)
	if err != nil {
		return logical.ErrorResponse("could not load provider"), nil
	}
	b.provider = provider

	roleName := d.Get("role").(string)
	if roleName == "" {
		roleName = config.DefaultRole
	}
	if roleName == "" {
		return logical.ErrorResponse("missing role"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q could not be found", roleName), nil
	}

	token := d.Get("jwt").(string)
	if len(token) == 0 {
		return logical.ErrorResponse("missing token"), nil
	}

	// Here is where things diverge. If it is using OIDC Discovery, validate that way;
	// otherwise validate against the locally configured or JWKS keys. Once things are
	// validated, we re-unify the request path when evaluating the claims.
	allClaims := map[string]interface{}{}

	payload, err := b.provider.Verify(ctx, token)
	if err != nil {
		return logical.ErrorResponse(errwrap.Wrapf("error verifying token: {{err}}", err).Error()), nil
	}
	if err := payload.Claims(&allClaims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %v", err)
	}

	// get group claims from Cloudflare
	groupClaimsURL := fmt.Sprintf("%s/cdn-cgi/access/get-identity", config.AuthDomain)
	groupRequest, err := http.NewRequestWithContext(ctx, "GET", groupClaimsURL, nil)

	if err != nil {
		return logical.ErrorResponse(errwrap.Wrapf("error forming request for group claims: {{err}}", err).Error()), nil
	}
	groupRequest.AddCookie(&http.Cookie{Name: "CF_Authorization", Value: token})
	resp, err := http.DefaultClient.Do(groupRequest)

	if err != nil {
		return logical.ErrorResponse(errwrap.Wrapf("error getting response for group claims: {{err}}", err).Error()), nil
	}

	groupClaims := groupClaims{}
	by, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return logical.ErrorResponse(errwrap.Wrapf("error reading response for group claims: {{err}}", err).Error()), nil
	}

	if err := json.Unmarshal(by, &groupClaims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal group claims: %v", err)
	}
	groups := make([]interface{}, 0)
	for _, value := range groupClaims.Groups {
		groups = append(groups, value.ID)
	}
	allClaims["groups"] = groups

	if err := validateBoundClaims(b.Logger(), role.BoundClaimsType, role.BoundClaims, allClaims); err != nil {
		return logical.ErrorResponse("error validating claims: %s", err.Error()), nil
	}

	alias, groupAliases, err := b.createIdentity(allClaims, role)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	tokenMetadata := map[string]string{"role": roleName}
	for k, v := range alias.Metadata {
		tokenMetadata[k] = v
	}

	auth := &logical.Auth{
		DisplayName:  alias.Name,
		Alias:        alias,
		GroupAliases: groupAliases,
		InternalData: map[string]interface{}{
			"role": roleName,
		},
		Metadata: tokenMetadata,
	}

	role.PopulateTokenAuth(auth)

	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *jwtAuthBackend) pathLoginRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := req.Auth.InternalData["role"].(string)
	if roleName == "" {
		return nil, errors.New("failed to fetch role_name during renewal")
	}

	// Ensure that the Role still exists.
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to validate role %s during renewal: {{err}}", roleName), err)
	}
	if role == nil {
		return nil, fmt.Errorf("role %s does not exist during renewal", roleName)
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = role.TokenTTL
	resp.Auth.MaxTTL = role.TokenMaxTTL
	resp.Auth.Period = role.TokenPeriod
	return resp, nil
}

// createIdentity creates an alias and set of groups aliases based on the role
// definition and received claims.
func (b *jwtAuthBackend) createIdentity(allClaims map[string]interface{}, role *jwtRole) (*logical.Alias, []*logical.Alias, error) {
	userClaimRaw, ok := allClaims[role.UserClaim]
	if !ok {
		return nil, nil, fmt.Errorf("claim %q not found in token", role.UserClaim)
	}
	userName, ok := userClaimRaw.(string)
	if !ok {
		return nil, nil, fmt.Errorf("claim %q could not be converted to string", role.UserClaim)
	}

	metadata, err := extractMetadata(b.Logger(), allClaims, role.ClaimMappings)
	if err != nil {
		return nil, nil, err
	}

	alias := &logical.Alias{
		Name:     userName,
		Metadata: metadata,
	}

	var groupAliases []*logical.Alias

	if role.GroupsClaim == "" {
		return alias, groupAliases, nil
	}

	groupsClaimRaw := getClaim(b.Logger(), allClaims, role.GroupsClaim)

	if groupsClaimRaw == nil {
		return nil, nil, fmt.Errorf("%q claim not found in token", role.GroupsClaim)
	}

	groups, ok := normalizeList(groupsClaimRaw)

	if !ok {
		return nil, nil, fmt.Errorf("%q claim could not be converted to string list", role.GroupsClaim)
	}
	for _, groupRaw := range groups {
		group, ok := groupRaw.(string)
		if !ok {
			return nil, nil, fmt.Errorf("value %v in groups claim could not be parsed as string", groupRaw)
		}
		if group == "" {
			continue
		}
		groupAliases = append(groupAliases, &logical.Alias{
			Name: group,
		})
	}

	return alias, groupAliases, nil
}

const (
	pathLoginHelpSyn = `
	Authenticates to Vault using a JWT (or OIDC) token.
	`
	pathLoginHelpDesc = `
Authenticates JWTs.
`
)
