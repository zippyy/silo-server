package plugins

import (
	"context"
	"errors"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestPluginConnectionCheckCapabilityUsesExactAuthConfigMapping(t *testing.T) {
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
		authTestCapability(t, "ldap", []any{"ldap"}),
		{Type: "request_router.v1", Id: "ldap"},
		{Type: "metadata_provider.v1", Id: "metadata"},
	}}

	capability, err := pluginConnectionCheckCapabilityForManifest(manifest, "ldap")
	if err != nil {
		t.Fatalf("pluginConnectionCheckCapabilityForManifest() error = %v", err)
	}
	if capability.kind != connectionCheckKindAuth || capability.id != "ldap" {
		t.Fatalf("capability = %#v, want auth provider ldap", capability)
	}
}

func TestPluginConnectionCheckCapabilitySelectsAmongMultipleAuthProviders(t *testing.T) {
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
		authTestCapability(t, "ldap", []any{"ldap"}),
		{Type: "request_router.v1", Id: "ldap"},
		authTestCapability(t, "oidc", []any{"oidc"}),
		{Type: "request_router.v1", Id: "oidc"},
	}}

	capability, err := pluginConnectionCheckCapabilityForManifest(manifest, "oidc")
	if err != nil {
		t.Fatalf("pluginConnectionCheckCapabilityForManifest() error = %v", err)
	}
	if capability.id != "oidc" {
		t.Fatalf("capability = %#v, want oidc", capability)
	}
}

func TestPluginConnectionCheckCapabilityRejectsAmbiguousAuthMapping(t *testing.T) {
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
		authTestCapability(t, "ldap-one", []any{"ldap"}),
		{Type: "request_router.v1", Id: "ldap-one"},
		authTestCapability(t, "ldap-two", []any{"ldap"}),
		{Type: "request_router.v1", Id: "ldap-two"},
	}}

	_, err := pluginConnectionCheckCapabilityForManifest(manifest, "ldap")
	if !errors.Is(err, ErrConnectionTestUnsupported) {
		t.Fatalf("error = %v, want ambiguity failure", err)
	}
}

func TestPluginConnectionCheckCapabilityRejectsMissingAuthMappingWithoutMetadataFallback(t *testing.T) {
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
		authTestCapability(t, "ldap", []any{"other"}),
		{Type: "request_router.v1", Id: "ldap"},
		{Type: "metadata_provider.v1", Id: "metadata"},
	}}

	_, err := pluginConnectionCheckCapabilityForManifest(manifest, "ldap")
	if !errors.Is(err, ErrConnectionTestUnsupported) {
		t.Fatalf("error = %v, want missing mapping failure", err)
	}
}

func TestPluginConnectionCheckCapabilityRejectsMalformedAuthAdvertisement(t *testing.T) {
	tests := []map[string]any{
		{"connection_test": true},
		{"connection_test": "true", "connection_test_config_keys": []any{"ldap"}},
		{"connection_test": true, "connection_test_config_keys": "ldap"},
		{"connection_test": true, "connection_test_config_keys": []any{"ldap", "ldap"}},
	}
	for _, metadataMap := range tests {
		metadata, err := structpb.NewStruct(metadataMap)
		if err != nil {
			t.Fatal(err)
		}
		manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
			{Type: "auth_provider.v1", Id: "ldap", Metadata: metadata},
			{Type: "request_router.v1", Id: "ldap"},
			{Type: "metadata_provider.v1", Id: "metadata"},
		}}
		if _, err := pluginConnectionCheckCapabilityForManifest(manifest, "ldap"); !errors.Is(err, ErrConnectionTestUnsupported) {
			t.Fatalf("metadata %#v error = %v, want malformed failure", metadataMap, err)
		}
	}
}

func TestPluginConnectionCheckCapabilityRejectsUnsupportedRouterVersion(t *testing.T) {
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
		authTestCapability(t, "ldap", []any{"ldap"}),
		{Type: "request_router.v2", Id: "ldap"},
	}}
	_, err := pluginConnectionCheckCapabilityForManifest(manifest, "ldap")
	if !errors.Is(err, ErrConnectionTestUnsupported) {
		t.Fatalf("error = %v, want unsupported version failure", err)
	}
}

func TestRunAuthProviderConnectionCheckRequiresPositiveAcknowledgement(t *testing.T) {
	original := requestRouterConnectionTest
	t.Cleanup(func() { requestRouterConnectionTest = original })
	client := &fakePluginClient{}

	for _, test := range []struct {
		name     string
		response *pluginv1.TestConnectionResponse
		wantErr  bool
	}{
		{name: "positive", response: &pluginv1.TestConnectionResponse{Ok: true}},
		{name: "negative", response: &pluginv1.TestConnectionResponse{Ok: false}, wantErr: true},
		{name: "missing", response: nil, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			requestRouterConnectionTest = func(context.Context, pluginClient, string) (*pluginv1.TestConnectionResponse, error) {
				return test.response, nil
			}
			err := runAuthProviderConnectionCheck(context.Background(), client, "ldap")
			if (err != nil) != test.wantErr {
				t.Fatalf("runAuthProviderConnectionCheck() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func authTestCapability(t *testing.T, id string, configKeys []any) *pluginv1.CapabilityDescriptor {
	t.Helper()
	metadata, err := structpb.NewStruct(map[string]any{
		"connection_test":             true,
		"connection_test_config_keys": configKeys,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &pluginv1.CapabilityDescriptor{Type: "auth_provider.v1", Id: id, Metadata: metadata}
}
