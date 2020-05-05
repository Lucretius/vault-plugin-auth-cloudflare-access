package jwtauth

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/coreos/go-oidc"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/patrickmn/go-cache"
)

const (
	configPath string = "config"
	rolePrefix string = "role/"
)

// Factory is used by framework
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type jwtAuthBackend struct {
	*framework.Backend

	l            sync.RWMutex
	provider     *oidc.IDTokenVerifier
	keySet       oidc.KeySet
	cachedConfig *jwtConfig
	oidcStates   *cache.Cache

	providerCtx       context.Context
	providerCtxCancel context.CancelFunc
}

func backend() *jwtAuthBackend {
	b := new(jwtAuthBackend)
	b.providerCtx, b.providerCtxCancel = context.WithCancel(context.Background())

	b.Backend = &framework.Backend{
		AuthRenew:   b.pathLoginRenew,
		BackendType: logical.TypeCredential,
		Invalidate:  b.invalidate,
		Help:        backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
				"oidc/auth_url",
				"oidc/callback",

				// Uncomment to mount simple UI handler for local development
				// "ui",
			},
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathLogin(b),
				pathRoleList(b),
				pathRole(b),
				pathConfig(b),

				// Uncomment to mount simple UI handler for local development
				// pathUI(b),
			},
		),
		Clean: b.cleanup,
	}

	return b
}

func (b *jwtAuthBackend) cleanup(_ context.Context) {
	b.l.Lock()
	if b.providerCtxCancel != nil {
		b.providerCtxCancel()
	}
	b.l.Unlock()
}

func (b *jwtAuthBackend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config":
		b.reset()
	}
}

func (b *jwtAuthBackend) reset() {
	b.l.Lock()
	b.provider = nil
	b.cachedConfig = nil
	b.l.Unlock()
}

func (b *jwtAuthBackend) getProvider(config *jwtConfig) (*oidc.IDTokenVerifier, error) {
	b.l.RLock()
	unlockFunc := b.l.RUnlock
	defer func() { unlockFunc() }()

	if b.provider != nil {
		return b.provider, nil
	}

	b.l.RUnlock()
	b.l.Lock()
	unlockFunc = b.l.Unlock

	if b.provider != nil {
		return b.provider, nil
	}

	provider, err := b.createProvider(config)
	if err != nil {
		return nil, err
	}

	b.provider = provider
	return provider, nil
}

func (b *jwtAuthBackend) createProvider(config *jwtConfig) (*oidc.IDTokenVerifier, error) {
	_, err := b.getKeySet(config)
	if err != nil {
		return nil, errors.New("provider error: keyset retrieval error")
	}
	if config.AuthDomain == "" {
		return nil, errors.New("provider error: audience_tag not configured")
	}
	oauthConfig := &oidc.Config{
		ClientID: config.AudienceTag,
	}
	return oidc.NewVerifier(config.AuthDomain, b.keySet, oauthConfig), nil
}

// getKeySet returns a new JWKS KeySet based on the provided config.
func (b *jwtAuthBackend) getKeySet(config *jwtConfig) (oidc.KeySet, error) {
	if b.keySet != nil {
		return b.keySet, nil
	}

	if config.AuthDomain == "" {
		return nil, errors.New("keyset error: auth_domain not configured")
	}
	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", config.AuthDomain)
	b.keySet = oidc.NewRemoteKeySet(b.providerCtx, certsURL)

	return b.keySet, nil
}

const (
	backendHelp = `
The JWT backend plugin allows authentication using JWTs (including OIDC).
`
)
