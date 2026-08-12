package plugins

import (
	"context"
	"errors"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestPluginConnectionCheckRejectsUnadvertisedAuthProviderConfig(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []*pluginv1.CapabilityDescriptor
	}{
		{
			name: "single auth provider",
			capabilities: []*pluginv1.CapabilityDescriptor{
				{Type: authProviderCapabilityType, Id: "ldap"},
			},
		},
		{
			name: "multiple auth providers do not select by order",
			capabilities: []*pluginv1.CapabilityDescriptor{
				{Type: authProviderCapabilityType, Id: "ldap"},
				{Type: authProviderCapabilityType, Id: "oidc"},
			},
		},
		{
			name: "metadata provider is not an auth fallback",
			capabilities: []*pluginv1.CapabilityDescriptor{
				{Type: authProviderCapabilityType, Id: "ldap"},
				{Type: "metadata_provider.v1", Id: "metadata"},
			},
		},
		{
			name: "legacy malformed advertisement stays unsupported",
			capabilities: []*pluginv1.CapabilityDescriptor{
				authCapabilityWithMetadata(t, map[string]any{
					"connection_test":             "true",
					"connection_test_config_keys": []any{"ldap"},
				}),
				{Type: "metadata_provider.v1", Id: "metadata"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := &pluginv1.PluginManifest{Capabilities: test.capabilities}
			capability, err := pluginConnectionCheckCapabilityForManifest(manifest, "ldap")
			if !errors.Is(err, ErrConnectionTestUnsupported) {
				t.Fatalf("selection error = %v, want ErrConnectionTestUnsupported", err)
			}
			if capability.kind != "" || capability.id != "" || len(capability.configKeys) != 0 {
				t.Fatalf("unsupported auth check selected capability %#v", capability)
			}
		})
	}
}

func TestPluginConnectionCheckSelectsTypedAuthProvider(t *testing.T) {
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
		{
			Type: authProviderCapabilityType,
			Id:   "ldap",
			AuthProvider: &pluginv1.AuthProviderDescriptor{
				ConnectionTest: &pluginv1.AuthProviderConnectionTestDescriptor{
					ConfigKeys: []string{"ldap", "tls"},
				},
			},
		},
		{Type: "metadata_provider.v1", Id: "metadata"},
	}}

	capability, err := pluginConnectionCheckCapabilityForManifest(manifest, "ldap")
	if err != nil {
		t.Fatal(err)
	}
	if capability.kind != connectionCheckKindAuth || capability.id != "ldap" {
		t.Fatalf("capability = %#v, want typed ldap auth provider", capability)
	}
	if len(capability.configKeys) != 2 || capability.configKeys[0] != "ldap" || capability.configKeys[1] != "tls" {
		t.Fatalf("config keys = %#v, want [ldap tls]", capability.configKeys)
	}

	if _, err := pluginConnectionCheckCapabilityForManifest(manifest, "metadata"); !errors.Is(err, ErrConnectionTestUnsupported) {
		t.Fatalf("unowned auth config selection error = %v, want unsupported", err)
	}
}

func TestPluginConnectionCheckRejectsAmbiguousTypedAuthProviders(t *testing.T) {
	descriptor := func(id string) *pluginv1.CapabilityDescriptor {
		return &pluginv1.CapabilityDescriptor{
			Type: authProviderCapabilityType,
			Id:   id,
			AuthProvider: &pluginv1.AuthProviderDescriptor{
				ConnectionTest: &pluginv1.AuthProviderConnectionTestDescriptor{ConfigKeys: []string{"directory"}},
			},
		}
	}
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
		descriptor("ldap"),
		descriptor("ad"),
	}}

	if _, err := pluginConnectionCheckCapabilityForManifest(manifest, "directory"); !errors.Is(err, ErrConnectionTestUnsupported) {
		t.Fatalf("ambiguous selection error = %v, want unsupported", err)
	}
}

func TestAuthProviderConnectionTestEntriesContainOnlyDeclaredProspectiveConfig(t *testing.T) {
	ldapValue, err := structpb.NewStruct(map[string]any{"url": "ldaps://directory.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	unrelatedValue, err := structpb.NewStruct(map[string]any{"token": "must-not-leak"})
	if err != nil {
		t.Fatal(err)
	}
	ldapEntry := &pluginv1.ConfigEntry{Key: "ldap", Value: ldapValue}
	entries := authProviderConnectionTestEntries(
		[]string{"ldap", "tls"},
		[]*pluginv1.ConfigEntry{
			ldapEntry,
			{Key: "unrelated", Value: unrelatedValue},
		},
	)
	if len(entries) != 2 || entries[0].GetKey() != "ldap" || entries[1].GetKey() != "tls" {
		t.Fatalf("owned entries = %#v, want ldap and tls", entries)
	}
	if entries[0] == ldapEntry {
		t.Fatal("prospective config entry was not cloned")
	}
	if got := entries[0].GetValue().AsMap()["url"]; got != "ldaps://directory.example.com" {
		t.Fatalf("ldap URL = %#v", got)
	}
	if entries[1].GetValue() == nil || len(entries[1].GetValue().GetFields()) != 0 {
		t.Fatalf("missing declared entry = %#v, want empty object", entries[1])
	}
}

func TestServiceAuthConnectionCheckScopesTemporaryRuntimeConfig(t *testing.T) {
	originalProbe := runPluginConnectionCheck
	t.Cleanup(func() { runPluginConnectionCheck = originalProbe })
	runPluginConnectionCheck = func(
		_ context.Context,
		_ pluginClient,
		_ *pluginv1.PluginManifest,
		_ string,
		entries []*pluginv1.ConfigEntry,
	) error {
		if len(entries) != 1 || entries[0].GetKey() != "ldap" {
			t.Fatalf("probe entries = %#v, want only ldap", entries)
		}
		return nil
	}

	manifest := connectionTestManifest(t, "test.auth", "1.0.0")
	manifest.GlobalConfigSchema = []*pluginv1.ConfigSchema{
		{Key: "ldap", JsonSchema: `{"type":"object","additionalProperties":true}`},
		{Key: "unrelated", JsonSchema: `{"type":"object","additionalProperties":true}`},
	}
	manifest.Capabilities = []*pluginv1.CapabilityDescriptor{{
		Type: authProviderCapabilityType,
		Id:   "ldap",
		AuthProvider: &pluginv1.AuthProviderDescriptor{
			ConnectionTest: &pluginv1.AuthProviderConnectionTestDescriptor{ConfigKeys: []string{"ldap"}},
		},
	}}
	installPath := writeInstalledPluginManifest(t, manifest)
	host := &fakeServiceHost{startResult: &fakePluginClient{manifest: manifest}}
	service := &Service{
		installations: newFakeServiceInstallationStore(&Installation{
			ID: 8, PluginID: manifest.GetPluginId(), Version: manifest.GetVersion(), InstallPath: installPath,
		}),
		configs: &fakeServiceConfigStore{configsByInstallation: map[int][]*RuntimeConfig{
			8: {{InstallationID: 8, Key: "unrelated", Value: map[string]any{"secret": "must-not-reach-auth-plugin"}}},
		}},
		host: host,
	}

	if err := service.TestGlobalConfig(context.Background(), 8, "ldap", map[string]any{"url": "ldaps://directory.example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(host.started) != 1 || len(host.started[0].Config) != 1 || host.started[0].Config[0].GetKey() != "ldap" {
		t.Fatalf("temporary runtime config = %#v, want only ldap", host.started)
	}
}

func TestPluginConnectionCheckStillSelectsMetadataOnlyProvider(t *testing.T) {
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
		{Type: "metadata_provider.v1", Id: "metadata"},
	}}
	capability, err := pluginConnectionCheckCapabilityForManifest(manifest, "metadata")
	if err != nil {
		t.Fatal(err)
	}
	if capability.kind != connectionCheckKindMetadata || capability.id != "metadata" {
		t.Fatalf("capability = %#v, want metadata provider", capability)
	}
}

func authCapabilityWithMetadata(t *testing.T, metadata map[string]any) *pluginv1.CapabilityDescriptor {
	t.Helper()
	value, err := structpb.NewStruct(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return &pluginv1.CapabilityDescriptor{Type: authProviderCapabilityType, Id: "ldap", Metadata: value}
}
