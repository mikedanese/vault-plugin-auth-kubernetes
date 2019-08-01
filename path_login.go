package kubeauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/briankassouf/jose/jws"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathLogin returns the path configurations for login endpoints
func pathLogin(b *kubeAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: `Name of the role against which the login is being attempted. This field is required`,
			},
			"jwt": {
				Type:        framework.TypeString,
				Description: `A signed JWT for authenticating a service account. This field is required.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation:         b.pathLogin(),
			logical.AliasLookaheadOperation: b.aliasLookahead(),
		},

		HelpSynopsis:    pathLoginHelpSyn,
		HelpDescription: pathLoginHelpDesc,
	}
}

// pathLogin is used to authenticate to this backend
func (b *kubeAuthBackend) pathLogin() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		roleName := data.Get("role").(string)
		if len(roleName) == 0 {
			return logical.ErrorResponse("missing role"), nil
		}

		jwtStr := data.Get("jwt").(string)
		if len(jwtStr) == 0 {
			return logical.ErrorResponse("missing jwt"), nil
		}

		b.l.RLock()
		defer b.l.RUnlock()

		role, err := b.role(ctx, req.Storage, roleName)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return logical.ErrorResponse(fmt.Sprintf("invalid role name \"%s\"", roleName)), nil
		}

		// Check for a CIDR match.
		if len(role.TokenBoundCIDRs) > 0 {
			if req.Connection == nil {
				b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
				return nil, logical.ErrPermissionDenied
			}
			if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.TokenBoundCIDRs) {
				return nil, logical.ErrPermissionDenied
			}
		}

		config, err := b.config(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		if config == nil {
			return nil, errors.New("could not load backend configuration")
		}

		auth, err := authenticateLegacy(jwtStr, config.PublicKeys, b.reviewFactory(config))
		if err != nil {
			return nil, err
		}
		auth.InternalData = map[string]interface{}{
			"role": roleName,
		}

		role.PopulateTokenAuth(auth)

		// verify the namespace is allowed
		if len(role.ServiceAccountNamespaces) != 0 {
			if !strutil.StrListContainsGlob(role.ServiceAccountNamespaces, auth.Metadata["service_account_namespace"]) {
				return nil, errors.New("namespace not authorized")
			}
		}

		// verify the service account name is allowed
		if len(role.ServiceAccountNames) != 0 {
			if !strutil.StrListContainsGlob(role.ServiceAccountNames, auth.Metadata["service_account_name"]) {
				return nil, errors.New("service account name not authorized")
			}
		}

		return &logical.Response{
			Auth: auth,
		}, nil
	}
}

// aliasLookahead returns the alias object with the SA UID from the JWT
// Claims.
func (b *kubeAuthBackend) aliasLookahead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		jwtStr := data.Get("jwt").(string)
		if len(jwtStr) == 0 {
			return logical.ErrorResponse("missing jwt"), nil
		}

		// Parse into JWT
		parsedJWT, err := jws.ParseJWT([]byte(jwtStr))
		if err != nil {
			return nil, err
		}

		saUID, ok := parsedJWT.Claims().Get(uidJWTClaimKey).(string)
		if !ok || saUID == "" {
			return nil, errors.New("could not parse UID from claims")
		}

		return &logical.Response{
			Auth: &logical.Auth{
				Alias: &logical.Alias{
					Name: saUID,
				},
			},
		}, nil
	}
}

// Invoked when the token issued by this backend is attempting a renewal.
func (b *kubeAuthBackend) pathLoginRenew() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		roleName := req.Auth.InternalData["role"].(string)
		if roleName == "" {
			return nil, fmt.Errorf("failed to fetch role_name during renewal")
		}

		b.l.RLock()
		defer b.l.RUnlock()

		// Ensure that the Role still exists.
		role, err := b.role(ctx, req.Storage, roleName)
		if err != nil {
			return nil, fmt.Errorf("failed to validate role %s during renewal:%s", roleName, err)
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
}

const pathLoginHelpSyn = `Authenticates Kubernetes service accounts with Vault.`
const pathLoginHelpDesc = `
Authenticate Kubernetes service accounts.
`
