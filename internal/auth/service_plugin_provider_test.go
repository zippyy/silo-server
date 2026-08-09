package auth

import "testing"

func TestFindOAuthInstallationRejectsMultipleCapabilities(t *testing.T) {
	service := NewService(nil, nil, nil, nil, nil, nil, nil)
	ldap := NewPluginProviderWithClientFactory(PluginProviderConfig{
		InstallationID: 42,
		CapabilityID:   "ldap",
	}, nil, nil, nil, nil)
	oidc := NewPluginProviderWithClientFactory(PluginProviderConfig{
		InstallationID: 42,
		CapabilityID:   "oidc",
	}, nil, nil, nil, nil)
	service.RegisterProvider(LoginProviderInfo{ID: "plugin:42:ldap"}, ldap)
	service.RegisterProvider(LoginProviderInfo{ID: "plugin:42:oidc"}, oidc)

	if got := service.FindOAuthInstallation(42); got != nil {
		t.Fatalf("ambiguous installation selected capability %q", got.CapabilityID())
	}
	if got := service.findPluginProvider(42, "ldap"); got != ldap {
		t.Fatalf("exact capability lookup = %p, want %p", got, ldap)
	}
	if got := service.findPluginProvider(42, "missing"); got != nil {
		t.Fatalf("missing capability lookup = %p, want nil", got)
	}
}
