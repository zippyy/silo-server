package plugins

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-server/internal/pluginhost"
)

var ErrConnectionTestUnsupported = errors.New("plugin connection test unsupported")

type ConnectionTestError struct {
	Message string
	Cause   error
}

func (e *ConnectionTestError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *ConnectionTestError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

type pluginConnectionCheckCapability struct {
	kind       string
	id         string
	configKeys []string
}

const (
	connectionCheckKindMetadata = "metadata_provider"
	connectionCheckKindAuth     = "auth_provider"
	authProviderCapabilityType  = "auth_provider.v1"
)

var runPluginConnectionCheck = func(
	ctx context.Context,
	client pluginClient,
	manifest *pluginv1.PluginManifest,
	configKey string,
	configEntries []*pluginv1.ConfigEntry,
) error {
	capability, err := pluginConnectionCheckCapabilityForManifest(manifest, configKey)
	if err != nil {
		return err
	}

	switch capability.kind {
	case connectionCheckKindAuth:
		return runAuthProviderConnectionCheck(ctx, client, capability, configEntries)
	case connectionCheckKindMetadata:
		return runMetadataProviderConnectionCheck(ctx, client, manifest, capability.id)
	default:
		return &ConnectionTestError{
			Message: "Connection checks are not supported for this plugin yet.",
			Cause:   ErrConnectionTestUnsupported,
		}
	}
}

func runAuthProviderConnectionCheck(
	ctx context.Context,
	client pluginClient,
	capability pluginConnectionCheckCapability,
	configEntries []*pluginv1.ConfigEntry,
) error {
	authClient, err := client.AuthProviderConfiguration(capability.id)
	if err != nil {
		return &ConnectionTestError{
			Message: "Failed to initialize the authentication provider connection check.",
			Cause:   err,
		}
	}

	ownedEntries := authProviderConnectionTestEntries(capability.configKeys, configEntries)

	response, err := authClient.TestConnection(ctx, &pluginv1.AuthProviderTestConnectionRequest{
		CapabilityId: capability.id,
		Config:       ownedEntries,
	})
	if err != nil {
		return &ConnectionTestError{
			Message: "Authentication-provider connection check failed.",
			Cause:   err,
		}
	}
	if response == nil || !response.GetOk() {
		message := "Authentication-provider connection check failed."
		if response != nil && strings.TrimSpace(response.GetMessage()) != "" {
			message = strings.TrimSpace(response.GetMessage())
		}
		return &ConnectionTestError{Message: message}
	}
	return nil
}

func authProviderConnectionTestEntries(
	configKeys []string,
	configEntries []*pluginv1.ConfigEntry,
) []*pluginv1.ConfigEntry {
	entriesByKey := make(map[string]*pluginv1.ConfigEntry, len(configEntries))
	for _, entry := range configEntries {
		if entry != nil {
			entriesByKey[entry.GetKey()] = entry
		}
	}
	ownedEntries := make([]*pluginv1.ConfigEntry, 0, len(configKeys))
	for _, key := range configKeys {
		if entry := entriesByKey[key]; entry != nil {
			ownedEntries = append(ownedEntries, proto.CloneOf(entry))
			continue
		}
		ownedEntries = append(ownedEntries, &pluginv1.ConfigEntry{
			Key:   key,
			Value: &structpb.Struct{},
		})
	}
	return ownedEntries
}

func runMetadataProviderConnectionCheck(
	ctx context.Context,
	client pluginClient,
	manifest *pluginv1.PluginManifest,
	capabilityID string,
) error {
	capability := metadataProviderConnectionCheckCapability(manifest, capabilityID)
	if !metadataProviderSupportsConnectionProbe(capability, "movie") {
		slog.DebugContext(ctx,
			"skipping metadata provider connection check for unsupported probe type", "component", "plugins",
			"plugin_id", manifest.GetPluginId(),
			"capability_id", capabilityID,
			"item_type", "movie",
		)
		return nil
	}

	metadataClient, err := client.MetadataProvider(capabilityID)
	if err != nil {
		return &ConnectionTestError{
			Message: fmt.Sprintf("Failed to initialize the metadata provider: %v", err),
			Cause:   err,
		}
	}

	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if _, err := metadataClient.Search(probeCtx, &pluginv1.SearchMetadataRequest{
		Query:    "The Matrix",
		ItemType: "movie",
		Year:     1999,
		Language: "en",
	}); err != nil {
		return &ConnectionTestError{
			Message: fmt.Sprintf("Connection check failed: %v", err),
			Cause:   err,
		}
	}

	return nil
}

func (s *Service) TestGlobalConfig(
	ctx context.Context,
	installationID int,
	key string,
	value map[string]any,
) error {
	return s.TestGlobalConfigWithClears(ctx, installationID, key, value, nil)
}

// TestGlobalConfigWithClears tests the exact prospective configuration,
// including explicit removals of saved secrets. This keeps a successful probe
// from describing credentials the operator has already staged for deletion.
func (s *Service) TestGlobalConfigWithClears(
	ctx context.Context,
	installationID int,
	key string,
	value map[string]any,
	clearSecrets []string,
) error {
	if strings.TrimSpace(key) == "" {
		return &ConnectionTestError{Message: "Config key is required"}
	}
	if s.host == nil {
		return fmt.Errorf("plugin host not configured")
	}

	installation, manifest, err := s.ensureInstallationCache(ctx, installationID, false)
	if err != nil {
		return err
	}

	if value == nil {
		value = map[string]any{}
	}
	submitted := value
	secretFields := GlobalConfigSecretFields(manifest, key)
	secretPaths := GlobalConfigSecretPaths(manifest, key)
	clearSet, err := validatedSecretClearSet(key, secretFields, clearSecrets)
	if err != nil {
		return &ConnectionTestError{Message: err.Error(), Cause: err}
	}
	value, err = s.preserveStoredSecrets(
		ctx,
		installationID,
		key,
		value,
		secretPaths,
	)
	if err != nil {
		return err
	}
	for field := range clearSet {
		delete(value, field)
	}
	projection := globalConfigValidationProjection(manifest, key, value, submitted)
	if err := ValidateGlobalConfigValue(manifest, key, projection); err != nil {
		return &ConnectionTestError{
			Message: err.Error(),
			Cause:   err,
		}
	}
	checkCapability, err := pluginConnectionCheckCapabilityForManifest(manifest, key)
	if err != nil {
		return err
	}

	configEntries, err := s.mergedGlobalConfigEntries(ctx, installationID, key, value)
	if err != nil {
		return err
	}
	if checkCapability.kind == connectionCheckKindAuth {
		// Runtime.Configure is process-wide, so scope the temporary instance as
		// well as the TestConnection RPC to the auth capability's declared keys.
		configEntries = authProviderConnectionTestEntries(checkCapability.configKeys, configEntries)
	}

	testInstallationID := -int(s.testConfigSeq.Add(1))
	client, err := s.host.Start(ctx, pluginhost.StartRequest{
		InstallationID: testInstallationID,
		BinaryPath:     installation.InstallPath,
		Manifest:       manifest,
		Config:         configEntries,
	})
	if err != nil {
		return &ConnectionTestError{
			Message: fmt.Sprintf("Failed to start the plugin with the test configuration: %v", err),
			Cause:   err,
		}
	}

	defer func() {
		if stopErr := s.host.Stop(testInstallationID); stopErr != nil && !errors.Is(stopErr, pluginhost.ErrClientNotFound) {
			slog.WarnContext(ctx,
				"stopping temporary plugin connection check instance failed", "component", "plugins",
				"installation_id", installationID,
				"test_installation_id", testInstallationID,
				"error", stopErr,
			)
		}
	}()

	return runPluginConnectionCheck(ctx, client, manifest, key, configEntries)
}

func (s *Service) mergedGlobalConfigEntries(
	ctx context.Context,
	installationID int,
	key string,
	value map[string]any,
) ([]*pluginv1.ConfigEntry, error) {
	configsByKey := make(map[string]map[string]any)

	if s.configs != nil {
		configs, err := s.configs.ListGlobalConfigs(ctx, installationID)
		if err != nil {
			return nil, fmt.Errorf("list plugin runtime configs for installation %d: %w", installationID, err)
		}
		for _, config := range configs {
			if config == nil {
				continue
			}
			configsByKey[config.Key] = cloneConfigMap(config.Value)
		}
	}

	configsByKey[key] = cloneConfigMap(value)
	return configEntriesFromValues(configsByKey, installationID)
}

func configEntriesFromValues(
	configsByKey map[string]map[string]any,
	installationID int,
) ([]*pluginv1.ConfigEntry, error) {
	if len(configsByKey) == 0 {
		return nil, nil
	}

	keys := make([]string, 0, len(configsByKey))
	for key := range configsByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	entries := make([]*pluginv1.ConfigEntry, 0, len(keys))
	for _, key := range keys {
		value := configsByKey[key]
		if value == nil {
			value = map[string]any{}
		}

		structValue, err := structpb.NewStruct(value)
		if err != nil {
			return nil, fmt.Errorf(
				"encode runtime config %q for installation %d: %w",
				key,
				installationID,
				err,
			)
		}

		entries = append(entries, &pluginv1.ConfigEntry{
			Key:   key,
			Value: structValue,
		})
	}

	return entries, nil
}

func cloneConfigMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(value))
	for key, entry := range value {
		cloned[key] = entry
	}
	return cloned
}

func pluginConnectionCheckCapabilityForManifest(
	manifest *pluginv1.PluginManifest,
	configKey string,
) (pluginConnectionCheckCapability, error) {
	var selected *pluginConnectionCheckCapability
	for _, descriptor := range manifest.GetCapabilities() {
		if descriptor.GetType() != authProviderCapabilityType {
			continue
		}
		if metadata := descriptor.GetMetadata().AsMap(); metadata != nil {
			if _, legacyTest := metadata["connection_test"]; legacyTest {
				return malformedAuthConnectionCheck(configKey)
			}
			if _, legacyKeys := metadata["connection_test_config_keys"]; legacyKeys {
				return malformedAuthConnectionCheck(configKey)
			}
		}
		connectionTest := descriptor.GetAuthProvider().GetConnectionTest()
		if connectionTest == nil {
			continue
		}
		if descriptor.GetId() == "" || len(connectionTest.GetConfigKeys()) == 0 {
			return malformedAuthConnectionCheck(configKey)
		}
		seenKeys := make(map[string]struct{}, len(connectionTest.GetConfigKeys()))
		for _, key := range connectionTest.GetConfigKeys() {
			if key == "" {
				return malformedAuthConnectionCheck(configKey)
			}
			if _, duplicate := seenKeys[key]; duplicate {
				return malformedAuthConnectionCheck(configKey)
			}
			seenKeys[key] = struct{}{}
		}
		if !containsString(connectionTest.GetConfigKeys(), configKey) {
			continue
		}
		if selected != nil {
			return pluginConnectionCheckCapability{}, &ConnectionTestError{
				Message: fmt.Sprintf("Multiple authentication providers advertise connection checks for configuration key %q.", configKey),
				Cause:   ErrConnectionTestUnsupported,
			}
		}
		selected = &pluginConnectionCheckCapability{
			kind:       connectionCheckKindAuth,
			id:         descriptor.GetId(),
			configKeys: append([]string(nil), connectionTest.GetConfigKeys()...),
		}
	}
	if selected != nil {
		return *selected, nil
	}
	if capabilityID, err := metadataProviderConnectionCheckCapabilityID(manifest); err == nil {
		return pluginConnectionCheckCapability{
			kind: connectionCheckKindMetadata,
			id:   capabilityID,
		}, nil
	}
	return pluginConnectionCheckCapability{}, &ConnectionTestError{
		Message: "Connection checks are not supported for this plugin yet.",
		Cause:   ErrConnectionTestUnsupported,
	}
}

func malformedAuthConnectionCheck(configKey string) (pluginConnectionCheckCapability, error) {
	return pluginConnectionCheckCapability{}, &ConnectionTestError{
		Message: fmt.Sprintf("Authentication-provider connection-check metadata is invalid for configuration key %q.", configKey),
		Cause:   ErrConnectionTestUnsupported,
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func metadataProviderConnectionCheckCapabilityID(manifest *pluginv1.PluginManifest) (string, error) {
	var capabilityID string
	for _, capability := range manifest.GetCapabilities() {
		if capability.GetType() != "metadata_provider.v1" {
			continue
		}
		if capabilityID != "" {
			return "", &ConnectionTestError{
				Message: "Multiple metadata providers are ambiguous for connection testing.",
				Cause:   ErrConnectionTestUnsupported,
			}
		}
		capabilityID = capability.GetId()
	}
	if capabilityID != "" {
		return capabilityID, nil
	}
	return "", &ConnectionTestError{
		Message: "Connection checks are not supported for this plugin yet.",
		Cause:   ErrConnectionTestUnsupported,
	}
}

func metadataProviderConnectionCheckCapability(
	manifest *pluginv1.PluginManifest,
	capabilityID string,
) *pluginv1.CapabilityDescriptor {
	for _, capability := range manifest.GetCapabilities() {
		if capability.GetType() == "metadata_provider.v1" && capability.GetId() == capabilityID {
			return capability
		}
	}
	return nil
}

func metadataProviderSupportsConnectionProbe(
	capability *pluginv1.CapabilityDescriptor,
	contentType string,
) bool {
	priorities, ok := metadataProviderDefaultPriorities(capability)
	if !ok {
		return true
	}
	return priorities[contentType] > 0
}

func metadataProviderDefaultPriorities(
	capability *pluginv1.CapabilityDescriptor,
) (map[string]float64, bool) {
	if capability == nil || capability.GetMetadata() == nil {
		return nil, false
	}

	metadataMap := capability.GetMetadata().AsMap()
	raw, ok := metadataMap["default_priority"]
	if !ok {
		nested, nestedOK := metadataMap["metadata"].(map[string]any)
		if !nestedOK {
			return nil, false
		}
		raw, ok = nested["default_priority"]
		if !ok {
			return nil, false
		}
	}

	rawMap, ok := raw.(map[string]any)
	if !ok {
		return nil, false
	}
	priorities := make(map[string]float64, len(rawMap))
	for key, value := range rawMap {
		switch v := value.(type) {
		case float64:
			priorities[key] = v
		case int:
			priorities[key] = float64(v)
		case int32:
			priorities[key] = float64(v)
		case int64:
			priorities[key] = float64(v)
		}
	}
	return priorities, len(priorities) > 0
}
