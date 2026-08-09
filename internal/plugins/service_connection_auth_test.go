package plugins

import (
	"errors"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestPluginConnectionCheckRejectsAuthProviderConfig(t *testing.T) {
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
			if capability != (pluginConnectionCheckCapability{}) {
				t.Fatalf("unsupported auth check selected capability %#v", capability)
			}
		})
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
