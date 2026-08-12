package pluginhost

import (
	"context"
	"errors"
	"net"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	sdkruntime "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type testAuthProviderConfigurationServer struct {
	pluginv1.UnimplementedAuthProviderConfigurationServer
	request *pluginv1.AuthProviderTestConnectionRequest
}

func (s *testAuthProviderConfigurationServer) TestConnection(
	_ context.Context,
	request *pluginv1.AuthProviderTestConnectionRequest,
) (*pluginv1.AuthProviderTestConnectionResponse, error) {
	s.request = request
	return &pluginv1.AuthProviderTestConnectionResponse{Ok: true, Message: "ok"}, nil
}

// makeTestClient constructs a Client with the given declared capabilities.
// It creates a lazy (non-connecting) gRPC ClientConn so that accessors which
// call c.rpc.<Capability>() do not panic — no real connection is made.
func makeTestClient(t *testing.T, capabilities []*pluginv1.CapabilityDescriptor) *Client {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	rpc := sdkruntime.NewClient(conn)
	manifest := &pluginv1.PluginManifest{Capabilities: capabilities}
	return newClient(0, rpc, manifest)
}

func TestClient_ScheduledTask_CapabilityGate(t *testing.T) {
	t.Run("absent capability returns error", func(t *testing.T) {
		c := makeTestClient(t, nil)
		_, err := c.ScheduledTask("missing")
		if err == nil {
			t.Fatal("expected error for missing scheduled_task.v1 capability, got nil")
		}
		if !errors.Is(err, ErrCapabilityNotFound) {
			t.Errorf("expected ErrCapabilityNotFound, got %v", err)
		}
	})

	t.Run("declared capability returns no error", func(t *testing.T) {
		c := makeTestClient(t, []*pluginv1.CapabilityDescriptor{
			{Type: "scheduled_task.v1", Id: "nightly"},
		})
		got, err := c.ScheduledTask("nightly")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("expected non-nil ScheduledTaskClient")
		}
	})

	t.Run("wrong id returns error", func(t *testing.T) {
		c := makeTestClient(t, []*pluginv1.CapabilityDescriptor{
			{Type: "scheduled_task.v1", Id: "nightly"},
		})
		_, err := c.ScheduledTask("weekly")
		if err == nil {
			t.Fatal("expected error for mismatched scheduled_task.v1 capability id, got nil")
		}
		if !errors.Is(err, ErrCapabilityNotFound) {
			t.Errorf("expected ErrCapabilityNotFound, got %v", err)
		}
	})
}

func TestClient_ScanSource_CapabilityGate(t *testing.T) {
	t.Run("absent capability returns error", func(t *testing.T) {
		c := makeTestClient(t, nil)
		_, err := c.ScanSource("missing")
		if err == nil {
			t.Fatal("expected error for missing scan_source.v1 capability, got nil")
		}
		if !errors.Is(err, ErrCapabilityNotFound) {
			t.Errorf("expected ErrCapabilityNotFound, got %v", err)
		}
	})

	t.Run("declared capability returns no error", func(t *testing.T) {
		c := makeTestClient(t, []*pluginv1.CapabilityDescriptor{
			{Type: "scan_source.v1", Id: "arr"},
		})
		got, err := c.ScanSource("arr")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("expected non-nil ScanSourceClient")
		}
	})

	t.Run("wrong id returns error", func(t *testing.T) {
		c := makeTestClient(t, []*pluginv1.CapabilityDescriptor{
			{Type: "scan_source.v1", Id: "arr"},
		})
		_, err := c.ScanSource("inotify")
		if err == nil {
			t.Fatal("expected error for mismatched scan_source.v1 capability id, got nil")
		}
		if !errors.Is(err, ErrCapabilityNotFound) {
			t.Errorf("expected ErrCapabilityNotFound, got %v", err)
		}
	})
}

func TestClient_MarkerProvider_CapabilityGate(t *testing.T) {
	t.Run("absent capability returns error", func(t *testing.T) {
		c := makeTestClient(t, nil)
		_, err := c.MarkerProvider("missing")
		if err == nil {
			t.Fatal("expected error for missing marker_provider.v1 capability, got nil")
		}
		if !errors.Is(err, ErrCapabilityNotFound) {
			t.Errorf("expected ErrCapabilityNotFound, got %v", err)
		}
	})

	t.Run("declared capability returns no error", func(t *testing.T) {
		c := makeTestClient(t, []*pluginv1.CapabilityDescriptor{
			{Type: "marker_provider.v1", Id: "markers"},
		})
		got, err := c.MarkerProvider("markers")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("expected non-nil MarkerProviderClient")
		}
	})

	t.Run("wrong id returns error", func(t *testing.T) {
		c := makeTestClient(t, []*pluginv1.CapabilityDescriptor{
			{Type: "marker_provider.v1", Id: "markers"},
		})
		_, err := c.MarkerProvider("other")
		if err == nil {
			t.Fatal("expected error for mismatched marker_provider.v1 capability id, got nil")
		}
		if !errors.Is(err, ErrCapabilityNotFound) {
			t.Errorf("expected ErrCapabilityNotFound, got %v", err)
		}
	})
}

func TestClient_ImageResolver_CapabilityGate(t *testing.T) {
	t.Run("absent capability returns error", func(t *testing.T) {
		c := makeTestClient(t, nil)
		_, err := c.ImageResolver("missing")
		if err == nil {
			t.Fatal("expected error for missing image_resolver.v1 capability, got nil")
		}
		if !errors.Is(err, ErrCapabilityNotFound) {
			t.Errorf("expected ErrCapabilityNotFound, got %v", err)
		}
	})

	t.Run("declared capability returns no error", func(t *testing.T) {
		c := makeTestClient(t, []*pluginv1.CapabilityDescriptor{
			{Type: "image_resolver.v1", Id: "tmdb"},
		})
		got, err := c.ImageResolver("tmdb")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("expected non-nil ImageResolverClient")
		}
	})

	t.Run("wrong id returns error", func(t *testing.T) {
		c := makeTestClient(t, []*pluginv1.CapabilityDescriptor{
			{Type: "image_resolver.v1", Id: "tmdb"},
		})
		_, err := c.ImageResolver("imdb")
		if err == nil {
			t.Fatal("expected error for mismatched image_resolver.v1 capability id, got nil")
		}
		if !errors.Is(err, ErrCapabilityNotFound) {
			t.Errorf("expected ErrCapabilityNotFound, got %v", err)
		}
	})
}

func TestClient_AuthProviderConfiguration_CapabilityGate(t *testing.T) {
	t.Run("auth provider without typed advertisement is rejected", func(t *testing.T) {
		client := makeTestClient(t, []*pluginv1.CapabilityDescriptor{{
			Type: "auth_provider.v1",
			Id:   "ldap",
		}})
		if _, err := client.AuthProviderConfiguration("ldap"); !errors.Is(err, ErrCapabilityNotFound) {
			t.Fatalf("error = %v, want ErrCapabilityNotFound", err)
		}
	})

	t.Run("typed connection test advertisement is accepted", func(t *testing.T) {
		client := makeTestClient(t, []*pluginv1.CapabilityDescriptor{{
			Type: "auth_provider.v1",
			Id:   "ldap",
			AuthProvider: &pluginv1.AuthProviderDescriptor{
				ConnectionTest: &pluginv1.AuthProviderConnectionTestDescriptor{ConfigKeys: []string{"ldap"}},
			},
		}})
		configuration, err := client.AuthProviderConfiguration("ldap")
		if err != nil {
			t.Fatal(err)
		}
		if configuration == nil {
			t.Fatal("configuration client is nil")
		}
	})
}

func TestAuthProviderConfigurationClientCallsDedicatedRPC(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	configurationServer := &testAuthProviderConfigurationServer{}
	pluginv1.RegisterAuthProviderConfigurationServer(server, configurationServer)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := newClient(1, sdkruntime.NewClient(conn), &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{{
		Type: "auth_provider.v1",
		Id:   "ldap",
		AuthProvider: &pluginv1.AuthProviderDescriptor{
			ConnectionTest: &pluginv1.AuthProviderConnectionTestDescriptor{ConfigKeys: []string{"ldap"}},
		},
	}}})
	authConfig, err := client.AuthProviderConfiguration("ldap")
	if err != nil {
		t.Fatal(err)
	}
	response, err := authConfig.TestConnection(context.Background(), &pluginv1.AuthProviderTestConnectionRequest{CapabilityId: "ldap"})
	if err != nil || !response.GetOk() {
		t.Fatalf("TestConnection() = %#v, %v", response, err)
	}
	if configurationServer.request.GetCapabilityId() != "ldap" {
		t.Fatalf("request = %#v", configurationServer.request)
	}
}
