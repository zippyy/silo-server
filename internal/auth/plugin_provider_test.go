package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestRandomPluginOnlyPasswordFitsBcryptLimit(t *testing.T) {
	password, err := randomPluginOnlyPassword()
	if err != nil {
		t.Fatalf("randomPluginOnlyPassword() error = %v", err)
	}
	if len(password) > 72 {
		t.Fatalf("password length = %d, want <= 72", len(password))
	}
	if _, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost); err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword() error = %v", err)
	}
}

func TestManagedRoleContractFromMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]any
		want     string
		wantErr  bool
	}{
		{name: "not advertised", metadata: map[string]any{}},
		{name: "v1", metadata: map[string]any{
			managedRoleContractMetadataKey: ManagedRoleContractV1,
			managedRoleValuesMetadataKey:   []any{"user", "admin"},
		}, want: ManagedRoleContractV1},
		{name: "unsupported version", metadata: map[string]any{
			managedRoleContractMetadataKey: "silo.auth.managed-role.v2",
			managedRoleValuesMetadataKey:   []any{"user", "admin"},
		}, wantErr: true},
		{name: "missing values", metadata: map[string]any{
			managedRoleContractMetadataKey: ManagedRoleContractV1,
		}, wantErr: true},
		{name: "extra role", metadata: map[string]any{
			managedRoleContractMetadataKey: ManagedRoleContractV1,
			managedRoleValuesMetadataKey:   []any{"user", "admin", "owner"},
		}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ManagedRoleContractFromMetadata(test.metadata)
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("ManagedRoleContractFromMetadata() = %q, %v; want %q, wantErr %v", got, err, test.want, test.wantErr)
			}
		})
	}
}

func TestManagedRoleContractForBindingRequiresOperatorAuthorization(t *testing.T) {
	metadata := map[string]any{
		managedRoleContractMetadataKey: ManagedRoleContractV1,
		managedRoleValuesMetadataKey:   []any{"user", "admin"},
	}
	contract, err := ManagedRoleContractForBinding(metadata, false)
	if err != nil {
		t.Fatal(err)
	}
	if contract != "" {
		t.Fatalf("unauthorized binding received managed-role contract %q", contract)
	}
	contract, err = ManagedRoleContractForBinding(metadata, true)
	if err != nil {
		t.Fatal(err)
	}
	if contract != ManagedRoleContractV1 {
		t.Fatalf("authorized binding contract = %q, want %q", contract, ManagedRoleContractV1)
	}
}

func TestManagedRoleFromResponseFailsClosed(t *testing.T) {
	tests := []struct {
		name        string
		claims      map[string]any
		authority   string
		wantRole    string
		wantManaged bool
		wantErr     bool
	}{
		{name: "normal auth has no claims"},
		{name: "bare admin ignored", claims: map[string]any{managedRoleClaimKey: "admin"}, authority: ManagedRoleContractV1},
		{name: "managed false ignored", claims: map[string]any{
			managedRoleMarkerClaimKey: false, managedRoleContractClaimKey: ManagedRoleContractV1, managedRoleClaimKey: "admin",
		}, authority: ManagedRoleContractV1},
		{name: "malformed marker", claims: map[string]any{managedRoleMarkerClaimKey: "true"}, authority: ManagedRoleContractV1, wantErr: true},
		{name: "unadvertised capability", claims: managedRoleClaims("admin"), wantErr: true},
		{name: "missing response contract", claims: map[string]any{
			managedRoleMarkerClaimKey: true, managedRoleClaimKey: "admin",
		}, authority: ManagedRoleContractV1, wantErr: true},
		{name: "wrong response contract", claims: map[string]any{
			managedRoleMarkerClaimKey: true, managedRoleContractClaimKey: "silo.auth.managed-role.v2", managedRoleClaimKey: "admin",
		}, authority: ManagedRoleContractV1, wantErr: true},
		{name: "invalid role", claims: map[string]any{
			managedRoleMarkerClaimKey: true, managedRoleContractClaimKey: ManagedRoleContractV1, managedRoleClaimKey: "owner",
		}, authority: ManagedRoleContractV1, wantErr: true},
		{name: "case variant rejected", claims: managedRoleClaims("ADMIN"), authority: ManagedRoleContractV1, wantErr: true},
		{name: "v1 admin", claims: managedRoleClaims("admin"), authority: ManagedRoleContractV1, wantRole: "admin", wantManaged: true},
		{name: "v1 user", claims: managedRoleClaims("user"), authority: ManagedRoleContractV1, wantRole: "user", wantManaged: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := &pluginv1.AuthenticateResponse{}
			if test.claims != nil {
				claims, err := structpb.NewStruct(test.claims)
				if err != nil {
					t.Fatal(err)
				}
				response.Claims = claims
			}
			role, managed, err := managedRoleFromResponse(response, test.authority)
			if (err != nil) != test.wantErr || role != test.wantRole || managed != test.wantManaged {
				t.Fatalf("managedRoleFromResponse() = %q, %v, %v; want %q, %v, wantErr %v",
					role, managed, err, test.wantRole, test.wantManaged, test.wantErr)
			}
		})
	}
}

func TestProvisionedFallbackEmailUsesStableIdentityNamespace(t *testing.T) {
	response := &pluginv1.AuthenticateResponse{ExternalSubject: "entryuuid:123"}
	first := provisionedEmail(response, PluginIdentityKey{InstallationID: 7, CapabilityID: "ldap", ExternalSubject: response.ExternalSubject})
	second := provisionedEmail(response, PluginIdentityKey{InstallationID: 7, CapabilityID: "other", ExternalSubject: response.ExternalSubject})
	if first == second {
		t.Fatalf("fallback emails collided across capability namespaces: %q", first)
	}
	if first != provisionedEmail(response, PluginIdentityKey{InstallationID: 7, CapabilityID: "ldap", ExternalSubject: response.ExternalSubject}) {
		t.Fatal("fallback email is not stable")
	}
}

func TestManagedRoleTransitionAuditLog(t *testing.T) {
	var output bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	provider := &PluginProvider{config: PluginProviderConfig{
		InstallationID:      42,
		CapabilityID:        "ldap",
		ManagedRoleContract: ManagedRoleContractV1,
	}}
	provider.logRoleTransition(context.Background(), 73, roleTransition{
		previous: managedRoleUser,
		next:     managedRoleAdmin,
		changed:  true,
	})

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode audit log: %v", err)
	}
	want := map[string]any{
		"msg":                    "plugin-managed user role changed",
		"component":              "auth",
		"plugin_installation_id": float64(42),
		"capability_id":          "ldap",
		"user_id":                float64(73),
		"previous_role":          managedRoleUser,
		"new_role":               managedRoleAdmin,
		"contract":               ManagedRoleContractV1,
	}
	for key, expected := range want {
		if record[key] != expected {
			t.Errorf("audit field %q = %#v, want %#v", key, record[key], expected)
		}
	}

	output.Reset()
	provider.logRoleTransition(context.Background(), 73, roleTransition{
		previous: managedRoleAdmin,
		next:     managedRoleAdmin,
		changed:  true,
	})
	if output.Len() != 0 {
		t.Fatalf("unchanged role emitted an audit record: %s", output.String())
	}
}

func managedRoleClaims(role string) map[string]any {
	return map[string]any{
		managedRoleMarkerClaimKey:   true,
		managedRoleContractClaimKey: ManagedRoleContractV1,
		managedRoleClaimKey:         role,
	}
}
