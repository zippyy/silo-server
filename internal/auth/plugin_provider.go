package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-server/internal/access"
	"github.com/Silo-Server/silo-server/internal/models"
	"github.com/Silo-Server/silo-server/internal/pluginhost"
	"github.com/Silo-Server/silo-server/internal/plugins"
)

var (
	ErrPluginEmailConflict        = errors.New("plugin identity email already belongs to another account")
	errProvisioningEmailCollision = errors.New("plugin provisioning email collision")
)

type pluginAuthClient interface {
	Authenticate(ctx context.Context, req *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error)
	InitAuthorize(ctx context.Context, req *pluginv1.InitAuthorizeRequest) (*pluginv1.InitAuthorizeResponse, error)
	ExchangeCode(ctx context.Context, req *pluginv1.ExchangeCodeRequest) (*pluginv1.AuthenticateResponse, error)
}

type pluginAuthClientFactory func(ctx context.Context) (pluginAuthClient, error)

// ManagedRoleBindingStore resolves the current operator authorization inside
// the role-transition transaction.
type ManagedRoleBindingStore interface {
	GetAuthBindingTx(ctx context.Context, tx pgx.Tx, installationID int, capabilityID string) (*plugins.AuthBinding, error)
}

// UserSessionRevoker invalidates compatibility sessions after a committed
// managed-role demotion.
type UserSessionRevoker func(ctx context.Context, userID int) error

// PluginProviderOption supplies runtime-owned authorization dependencies.
type PluginProviderOption func(*PluginProvider)

// WithManagedRoleBindingStore makes persisted auth-binding policy authoritative
// for every managed-role authentication.
func WithManagedRoleBindingStore(store ManagedRoleBindingStore) PluginProviderOption {
	return func(provider *PluginProvider) {
		provider.managedRoleBindings = store
	}
}

// WithUserSessionRevoker installs the post-commit compatibility-session hook.
func WithUserSessionRevoker(revoker UserSessionRevoker) PluginProviderOption {
	return func(provider *PluginProvider) {
		provider.compatSessions = revoker
	}
}

type PluginProviderConfig struct {
	InstallationID                int
	CapabilityID                  string
	DisplayName                   string
	AutoProvision                 bool
	AdvertisedManagedRoles        *pluginv1.AuthProviderManagedRoleDescriptor
	AdvertisedManagedRoleContract string
}

type PluginProvider struct {
	config              PluginProviderConfig
	client              pluginAuthClientFactory
	sessions            *SessionRepository
	users               *UserRepository
	identities          *PluginIdentityRepository
	accessGroups        *access.GroupStore
	managedRoleBindings ManagedRoleBindingStore
	compatSessions      UserSessionRevoker
}

func NewPluginProviderWithClientFactory(
	config PluginProviderConfig,
	sessions *SessionRepository,
	users *UserRepository,
	pool *pgxpool.Pool,
	clientFactory pluginAuthClientFactory,
	options ...PluginProviderOption,
) *PluginProvider {
	if config.AdvertisedManagedRoles != nil {
		config.AdvertisedManagedRoles = proto.CloneOf(config.AdvertisedManagedRoles)
	}
	provider := &PluginProvider{
		config:       config,
		client:       clientFactory,
		sessions:     sessions,
		users:        users,
		identities:   NewPluginIdentityRepository(pool),
		accessGroups: access.NewGroupStore(pool),
	}
	for _, option := range options {
		if option != nil {
			option(provider)
		}
	}
	return provider
}

func NewPluginProvider(
	config PluginProviderConfig,
	sessions *SessionRepository,
	users *UserRepository,
	pool *pgxpool.Pool,
	resolver interface {
		AuthProviderClient(ctx context.Context, installationID int, capabilityID string) (*pluginhost.AuthProviderClient, error)
	},
	options ...PluginProviderOption,
) *PluginProvider {
	return NewPluginProviderWithClientFactory(config, sessions, users, pool, func(ctx context.Context) (pluginAuthClient, error) {
		return resolver.AuthProviderClient(ctx, config.InstallationID, config.CapabilityID)
	}, options...)
}

func (p *PluginProvider) Authenticate(ctx context.Context, creds Credentials) (*models.User, error) {
	client, err := p.client(ctx)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrUserDisabled) {
			return nil, err
		}
		if errors.Is(err, plugins.ErrInstallationDisabled) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("load plugin auth client: %w", err)
	}

	response, err := client.Authenticate(ctx, &pluginv1.AuthenticateRequest{
		Username: creds.Username,
		Password: creds.Password,
	})
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrUserDisabled) {
			return nil, err
		}
		return nil, fmt.Errorf("plugin auth authenticate: %w", err)
	}
	return p.completeAuthentication(ctx, creds, response)
}

func (p *PluginProvider) CompleteOAuth(ctx context.Context, response *pluginv1.AuthenticateResponse) (*models.User, error) {
	return p.completeAuthentication(ctx, Credentials{}, response)
}

func (p *PluginProvider) completeAuthentication(
	ctx context.Context,
	creds Credentials,
	response *pluginv1.AuthenticateResponse,
) (*models.User, error) {
	if response.GetExternalSubject() == "" {
		return nil, ErrInvalidCredentials
	}
	key := p.identityKey(response.GetExternalSubject())
	user, err := p.lookupIdentityUser(ctx, key)
	if err == nil {
		if !user.Enabled {
			return nil, ErrUserDisabled
		}
		return p.synchronizeManagedRole(ctx, key, user, response)
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if !p.config.AutoProvision {
		return nil, ErrInvalidCredentials
	}
	return p.autoProvisionUser(ctx, key, creds, response)
}

func (p *PluginProvider) InstallationID() int { return p.config.InstallationID }

func (p *PluginProvider) CapabilityID() string { return p.config.CapabilityID }

func (p *PluginProvider) OAuthClient(ctx context.Context) (OAuthClient, error) {
	c, err := p.client(ctx)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (p *PluginProvider) ValidateSession(ctx context.Context, sessionID string) (bool, error) {
	if p.sessions == nil {
		return false, nil
	}
	if _, err := p.client(ctx); err != nil {
		if errors.Is(err, plugins.ErrInstallationDisabled) {
			return false, nil
		}
		return false, fmt.Errorf("load plugin auth client: %w", err)
	}
	return p.sessions.IsValid(ctx, sessionID)
}

func (p *PluginProvider) identityKey(externalSubject string) PluginIdentityKey {
	return PluginIdentityKey{
		InstallationID:  p.config.InstallationID,
		CapabilityID:    p.config.CapabilityID,
		ExternalSubject: externalSubject,
	}
}

func (p *PluginProvider) lookupIdentityUser(
	ctx context.Context,
	key PluginIdentityKey,
) (*models.User, error) {
	identity, err := p.identities.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	user, err := p.users.GetByID(ctx, identity.UserID)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (p *PluginProvider) autoProvisionUser(
	ctx context.Context,
	key PluginIdentityKey,
	creds Credentials,
	response *pluginv1.AuthenticateResponse,
) (*models.User, error) {
	usernameBase := provisionedUsernameBase(response, creds, p.config.InstallationID)
	email := provisionedEmail(response, key)
	password, err := randomPluginOnlyPassword()
	if err != nil {
		return nil, fmt.Errorf("generate plugin-only password: %w", err)
	}
	localPasswordLoginEnabled := false

	tx, err := p.identities.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin plugin user provisioning: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	desiredRole, roleManaged, err := p.managedRoleFromResponseTx(ctx, tx, response)
	if err != nil {
		return nil, err
	}

	if existing, getErr := p.identities.GetTx(ctx, tx, key, false); getErr == nil {
		if err := tx.Rollback(ctx); err != nil {
			return nil, fmt.Errorf("rollback duplicate plugin user provisioning: %w", err)
		}
		user, err := p.users.GetByID(ctx, existing.UserID)
		if err != nil {
			return nil, err
		}
		if !user.Enabled {
			return nil, ErrUserDisabled
		}
		return p.synchronizeManagedRole(ctx, key, user, response)
	} else if !errors.Is(getErr, ErrNotFound) {
		return nil, getErr
	}

	user, err := p.createProvisionedUserTx(ctx, tx, models.CreateUserInput{
		Email:                     email,
		Username:                  usernameBase,
		Password:                  password,
		LocalPasswordLoginEnabled: &localPasswordLoginEnabled,
		Role:                      managedRoleUser,
	}, key)
	if err != nil {
		if errors.Is(err, errProvisioningEmailCollision) {
			if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
				return nil, fmt.Errorf("rollback plugin email collision: %w", rollbackErr)
			}
			winner, lookupErr := p.lookupIdentityUser(ctx, key)
			if lookupErr == nil {
				if !winner.Enabled {
					return nil, ErrUserDisabled
				}
				return p.synchronizeManagedRole(ctx, key, winner, response)
			}
			if errors.Is(lookupErr, ErrNotFound) {
				return nil, ErrPluginEmailConflict
			}
			return nil, lookupErr
		}
		return nil, err
	}

	claimed, err := p.identities.ClaimTx(ctx, tx, key, user.ID)
	if err != nil {
		return nil, err
	}
	if !claimed {
		if err := tx.Rollback(ctx); err != nil {
			return nil, fmt.Errorf("rollback losing plugin identity claim: %w", err)
		}
		winner, err := p.lookupIdentityUser(ctx, key)
		if err != nil {
			return nil, err
		}
		if !winner.Enabled {
			return nil, ErrUserDisabled
		}
		return p.synchronizeManagedRole(ctx, key, winner, response)
	}

	transition := roleTransition{}
	if roleManaged {
		identity, err := p.identities.GetTx(ctx, tx, key, true)
		if err != nil {
			return nil, err
		}
		user, transition, err = p.applyManagedRoleTx(ctx, tx, identity, user, desiredRole)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit plugin user provisioning: %w", err)
	}
	p.handleCommittedRoleTransition(ctx, user.ID, transition)
	return p.users.GetByID(ctx, user.ID)
}

func (p *PluginProvider) createProvisionedUserTx(
	ctx context.Context,
	tx pgx.Tx,
	input models.CreateUserInput,
	key PluginIdentityKey,
) (*models.User, error) {
	digest := identityDigest(key)
	base := input.Username
	for attempt := 0; attempt < 10; attempt++ {
		input.Username = provisionedUsernameAttempt(base, digest, attempt)
		savepoint, err := tx.Begin(ctx)
		if err != nil {
			return nil, fmt.Errorf("begin plugin username attempt: %w", err)
		}
		user, createErr := p.users.CreateTx(ctx, savepoint, input)
		if createErr == nil {
			if err := savepoint.Commit(ctx); err != nil {
				return nil, fmt.Errorf("commit plugin username attempt: %w", err)
			}
			return user, nil
		}
		if err := savepoint.Rollback(ctx); err != nil {
			return nil, fmt.Errorf("rollback plugin username attempt: %w", err)
		}
		if !IsDuplicate(createErr) {
			return nil, fmt.Errorf("auto-provision plugin user: %w", createErr)
		}
		switch DuplicateConstraint(createErr) {
		case "users_username_key":
			continue
		case "users_email_key":
			return nil, errProvisioningEmailCollision
		default:
			return nil, fmt.Errorf("auto-provision plugin user: %w", createErr)
		}
	}
	return nil, fmt.Errorf("auto-provision plugin user: exhausted username attempts")
}

func (p *PluginProvider) synchronizeManagedRole(
	ctx context.Context,
	key PluginIdentityKey,
	user *models.User,
	response *pluginv1.AuthenticateResponse,
) (*models.User, error) {
	requested, err := managedRoleRequested(response)
	if err != nil {
		return nil, err
	}
	if !requested {
		return user, nil
	}

	tx, err := p.identities.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin managed-role synchronization: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	desiredRole, managed, err := p.managedRoleFromResponseTx(ctx, tx, response)
	if err != nil {
		return nil, err
	}
	if !managed {
		return user, nil
	}
	identity, err := p.identities.GetTx(ctx, tx, key, true)
	if err != nil {
		return nil, err
	}
	current, err := p.users.GetByIDTx(ctx, tx, identity.UserID, true)
	if err != nil {
		return nil, err
	}
	if !current.Enabled {
		return nil, ErrUserDisabled
	}
	updated, transition, err := p.applyManagedRoleTx(ctx, tx, identity, current, desiredRole)
	if err != nil {
		return nil, err
	}
	if !transition.changed {
		return current, nil
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit managed-role synchronization: %w", err)
	}
	p.handleCommittedRoleTransition(ctx, updated.ID, transition)
	return updated, nil
}

func (p *PluginProvider) managedRoleFromResponseTx(
	ctx context.Context,
	tx pgx.Tx,
	response *pluginv1.AuthenticateResponse,
) (string, bool, error) {
	operatorAuthorized := false
	hasAdvertisement := p.config.AdvertisedManagedRoles != nil ||
		p.config.AdvertisedManagedRoleContract == ManagedRoleContractV1
	if hasAdvertisement && p.managedRoleBindings != nil {
		binding, err := p.managedRoleBindings.GetAuthBindingTx(
			ctx, tx, p.config.InstallationID, p.config.CapabilityID,
		)
		if err != nil {
			if !errors.Is(err, plugins.ErrAuthBindingNotFound) {
				return "", false, fmt.Errorf("load managed-role authorization: %w", err)
			}
		} else if binding.Enabled && binding.ManagedRolesEnabled {
			operatorAuthorized = true
		}
	}
	return managedRoleFromResponse(
		response,
		p.config.AdvertisedManagedRoles,
		p.config.AdvertisedManagedRoleContract,
		operatorAuthorized,
	)
}

type roleTransition struct {
	previous string
	next     string
	changed  bool
}

func (p *PluginProvider) applyManagedRoleTx(
	ctx context.Context,
	tx pgx.Tx,
	identity *PluginAuthIdentity,
	user *models.User,
	desiredRole string,
) (*models.User, roleTransition, error) {
	transition := roleTransition{previous: user.Role, next: desiredRole}
	if desiredRole == managedRoleAdmin {
		if user.Role == managedRoleAdmin {
			return user, transition, nil
		}
		if !identity.SnapshotPresent {
			if err := p.identities.SaveManagedRoleSnapshotTx(
				ctx, tx, identity.ID, user.Permissions, user.AccessGroupID,
			); err != nil {
				return nil, transition, err
			}
		}
		role := managedRoleAdmin
		if err := p.users.UpdateTx(ctx, tx, user.ID, models.UpdateUserInput{
			Role:             &role,
			AccessGroupIDSet: true,
		}); err != nil {
			return nil, transition, fmt.Errorf("promote plugin-managed administrator: %w", err)
		}
		transition.changed = true
	} else {
		if user.Role == managedRoleUser && !identity.SnapshotPresent {
			return user, transition, nil
		}
		permissions := identity.SnapshotPermissions
		accessGroupID := identity.SnapshotAccessGroupID
		if !identity.SnapshotPresent {
			permissions = DefaultUserPermissions()
			var err error
			accessGroupID, err = p.accessGroups.DefaultIDTx(ctx, tx)
			if err != nil {
				return nil, transition, err
			}
		} else if identity.SnapshotAccessGroupPresent && accessGroupID == nil {
			var err error
			accessGroupID, err = p.accessGroups.DefaultIDTx(ctx, tx)
			if err != nil {
				return nil, transition, err
			}
		}
		role := managedRoleUser
		if err := p.users.UpdateTx(ctx, tx, user.ID, models.UpdateUserInput{
			Role:             &role,
			Permissions:      &permissions,
			AccessGroupIDSet: true,
			AccessGroupID:    accessGroupID,
		}); err != nil {
			return nil, transition, fmt.Errorf("demote plugin-managed administrator: %w", err)
		}
		if identity.SnapshotPresent {
			if err := p.identities.ClearManagedRoleSnapshotTx(ctx, tx, identity.ID); err != nil {
				return nil, transition, err
			}
		}
		if p.sessions == nil {
			return nil, transition, fmt.Errorf("demote plugin-managed administrator: session repository unavailable")
		}
		if err := p.sessions.RevokeAllByUserTx(ctx, tx, user.ID); err != nil {
			return nil, transition, fmt.Errorf("revoke demoted administrator sessions: %w", err)
		}
		transition.changed = user.Role != managedRoleUser || identity.SnapshotPresent
	}
	updated, err := p.users.GetByIDTx(ctx, tx, user.ID, false)
	if err != nil {
		return nil, transition, fmt.Errorf("reload plugin-managed user: %w", err)
	}
	return updated, transition, nil
}

func (p *PluginProvider) handleCommittedRoleTransition(ctx context.Context, userID int, transition roleTransition) {
	p.logRoleTransition(ctx, userID, transition)
	if !transition.changed || transition.previous != managedRoleAdmin || transition.next != managedRoleUser {
		return
	}
	if p.compatSessions == nil {
		slog.WarnContext(ctx, "compatibility session revocation unavailable after managed-role demotion",
			"component", "auth",
			"user_id", userID,
		)
		return
	}
	if err := p.compatSessions(ctx, userID); err != nil {
		slog.WarnContext(ctx, "compatibility session revocation failed after managed-role demotion",
			"component", "auth",
			"user_id", userID,
			"error", err,
		)
	}
}

func (p *PluginProvider) logRoleTransition(ctx context.Context, userID int, transition roleTransition) {
	if !transition.changed || transition.previous == transition.next {
		return
	}
	slog.InfoContext(ctx, "plugin-managed user role changed",
		"component", "auth",
		"plugin_installation_id", p.config.InstallationID,
		"capability_id", p.config.CapabilityID,
		"user_id", userID,
		"previous_role", transition.previous,
		"new_role", transition.next,
		"contract", p.managedRoleContractName(),
	)
}

func (p *PluginProvider) managedRoleContractName() string {
	if p.config.AdvertisedManagedRoles != nil {
		return ManagedRoleContractSDK
	}
	return p.config.AdvertisedManagedRoleContract
}

func provisionedUsernameBase(response *pluginv1.AuthenticateResponse, creds Credentials, installationID int) string {
	usernameBase := strings.TrimSpace(response.GetDisplayName())
	if usernameBase == "" {
		usernameBase = strings.TrimSpace(creds.Username)
	}
	if usernameBase == "" {
		usernameBase = response.GetExternalSubject()
	}
	usernameBase = sanitizeUsername(usernameBase)
	if len(usernameBase) > 48 {
		usernameBase = usernameBase[:48]
	}
	if usernameBase == "" {
		usernameBase = fmt.Sprintf("plugin_%d", installationID)
	}
	return usernameBase
}

func provisionedEmail(response *pluginv1.AuthenticateResponse, key PluginIdentityKey) string {
	if email := strings.TrimSpace(response.GetEmail()); email != "" {
		return email
	}
	digest := identityDigest(key)
	return fmt.Sprintf("plugin-%s@plugin-%d.local", digest[:24], key.InstallationID)
}

func provisionedUsernameAttempt(base, digest string, attempt int) string {
	if attempt == 0 {
		return base
	}
	if attempt == 1 {
		return fmt.Sprintf("%s_%s", base, digest[:8])
	}
	return fmt.Sprintf("%s_%s_%d", base, digest[:8], attempt)
}

func identityDigest(key PluginIdentityKey) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s", key.InstallationID, key.CapabilityID, key.ExternalSubject)))
	return hex.EncodeToString(sum[:])
}

func randomPluginOnlyPassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "plugin-only-" + hex.EncodeToString(buf), nil
}

func sanitizeUsername(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "_")
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			b.WriteRune(r)
		}
	}
	return strings.Trim(b.String(), "_.-")
}
