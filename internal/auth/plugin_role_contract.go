package auth

import (
	"fmt"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/proto"
)

const (
	ManagedRoleContractV1  = "silo.auth.managed-role.v1"
	ManagedRoleContractSDK = "sdk.auth_provider.managed_roles"
	managedRoleUser        = "user"
	managedRoleAdmin       = "admin"

	managedRoleContractMetadataKey = "managed_role_contract"
	managedRoleValuesMetadataKey   = "role_values"
	managedRoleContractClaimKey    = "silo_role_contract"
	managedRoleMarkerClaimKey      = "silo_role_managed"
	managedRoleClaimKey            = "silo_role"
)

// ManagedRoleDescriptorFromCapability returns the SDK-owned role contract only
// when it advertises the complete user/admin lifecycle Silo requires. A
// provider that can promote but cannot explicitly demote is not authorized.
func ManagedRoleDescriptorFromCapability(
	descriptor *pluginv1.CapabilityDescriptor,
) (*pluginv1.AuthProviderManagedRoleDescriptor, error) {
	if descriptor == nil || descriptor.GetAuthProvider().GetManagedRoles() == nil {
		return nil, nil
	}
	managedRoles := descriptor.GetAuthProvider().GetManagedRoles()
	if len(managedRoles.GetSupportedRoles()) != 2 {
		return nil, fmt.Errorf("managed-role descriptor must advertise exactly user and admin")
	}
	seen := make(map[pluginv1.ManagedSiloRole]struct{}, 2)
	for _, role := range managedRoles.GetSupportedRoles() {
		switch role {
		case pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_USER,
			pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_ADMIN:
		default:
			return nil, fmt.Errorf("managed-role descriptor contains unsupported role %v", role)
		}
		if _, duplicate := seen[role]; duplicate {
			return nil, fmt.Errorf("managed-role descriptor contains duplicate role %v", role)
		}
		seen[role] = struct{}{}
	}
	return proto.CloneOf(managedRoles), nil
}

func ManagedRoleContractFromMetadata(metadata map[string]any) (string, error) {
	contractValue, hasContract := metadata[managedRoleContractMetadataKey]
	roleValues, hasRoleValues := metadata[managedRoleValuesMetadataKey]
	if !hasContract && !hasRoleValues {
		return "", nil
	}
	contract, ok := contractValue.(string)
	if !ok || contract != ManagedRoleContractV1 {
		return "", fmt.Errorf("unsupported managed-role contract")
	}
	values, ok := strictStringSet(roleValues)
	if !ok || len(values) != 2 {
		return "", fmt.Errorf("managed-role contract must advertise exactly user and admin")
	}
	if _, ok := values[managedRoleUser]; !ok {
		return "", fmt.Errorf("managed-role contract does not advertise user")
	}
	if _, ok := values[managedRoleAdmin]; !ok {
		return "", fmt.Errorf("managed-role contract does not advertise admin")
	}
	return contract, nil
}

// ManagedRoleContractForBinding grants role authority only when both the
// installed capability advertises the supported contract and the operator has
// explicitly enabled it on this authentication binding.
func ManagedRoleContractForBinding(metadata map[string]any, enabled bool) (string, error) {
	contract, err := ManagedRoleContractFromMetadata(metadata)
	if err != nil {
		return "", err
	}
	if !enabled {
		return "", nil
	}
	return contract, nil
}

func managedRoleFromResponse(
	response *pluginv1.AuthenticateResponse,
	advertisedSDKRoles *pluginv1.AuthProviderManagedRoleDescriptor,
	legacyContract string,
	operatorAuthorized bool,
) (string, bool, error) {
	managed, err := managedRoleRequested(response)
	if err != nil || !managed {
		return "", false, err
	}
	if assertion := response.GetManagedSiloRole(); assertion != nil {
		if !operatorAuthorized || advertisedSDKRoles == nil {
			return "", false, fmt.Errorf("plugin is not authorized for managed roles")
		}
		var role string
		switch assertion.GetRole() {
		case pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_USER:
			role = managedRoleUser
		case pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_ADMIN:
			role = managedRoleAdmin
		default:
			return "", false, fmt.Errorf("plugin managed-role response contains an unsupported role")
		}
		if !managedRoleDescriptorSupports(advertisedSDKRoles, assertion.GetRole()) {
			return "", false, fmt.Errorf("plugin managed-role response was not advertised")
		}
		return role, true, nil
	}
	claims := response.GetClaims().AsMap()
	if !operatorAuthorized || legacyContract != ManagedRoleContractV1 {
		return "", false, fmt.Errorf("plugin is not authorized for managed roles")
	}
	contract, ok := claims[managedRoleContractClaimKey].(string)
	if !ok || contract != ManagedRoleContractV1 {
		return "", false, fmt.Errorf("plugin managed-role response uses an unsupported contract")
	}
	role, ok := claims[managedRoleClaimKey].(string)
	if !ok || (role != managedRoleUser && role != managedRoleAdmin) {
		return "", false, fmt.Errorf("plugin managed-role response contains an unsupported role")
	}
	return role, true, nil
}

func managedRoleRequested(response *pluginv1.AuthenticateResponse) (bool, error) {
	if response == nil {
		return false, nil
	}
	typed := response.GetManagedSiloRole() != nil
	if response.GetClaims() == nil {
		return typed, nil
	}
	claims := response.GetClaims().AsMap()
	rawMarker, hasMarker := claims[managedRoleMarkerClaimKey]
	_, hasContract := claims[managedRoleContractClaimKey]
	_, hasRole := claims[managedRoleClaimKey]
	if typed && (hasMarker || hasContract || hasRole) {
		return false, fmt.Errorf("plugin auth response mixes typed and legacy managed-role contracts")
	}
	if !hasMarker {
		return typed, nil
	}
	managed, ok := rawMarker.(bool)
	if !ok {
		return false, fmt.Errorf("plugin auth claim %q must be a boolean", managedRoleMarkerClaimKey)
	}
	return managed, nil
}

func managedRoleDescriptorSupports(
	descriptor *pluginv1.AuthProviderManagedRoleDescriptor,
	wanted pluginv1.ManagedSiloRole,
) bool {
	if descriptor == nil {
		return false
	}
	for _, role := range descriptor.GetSupportedRoles() {
		if role == wanted {
			return true
		}
	}
	return false
}

func strictStringSet(value any) (map[string]struct{}, bool) {
	raw, ok := value.([]any)
	if !ok || len(raw) == 0 {
		return nil, false
	}
	result := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, false
		}
		if _, duplicate := result[text]; duplicate {
			return nil, false
		}
		result[text] = struct{}{}
	}
	return result, true
}
