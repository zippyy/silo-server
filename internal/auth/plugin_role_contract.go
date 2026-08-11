package auth

import (
	"fmt"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

const (
	ManagedRoleContractV1 = "silo.auth.managed-role.v1"
	managedRoleUser       = "user"
	managedRoleAdmin      = "admin"

	managedRoleContractMetadataKey = "managed_role_contract"
	managedRoleValuesMetadataKey   = "role_values"
	managedRoleContractClaimKey    = "silo_role_contract"
	managedRoleMarkerClaimKey      = "silo_role_managed"
	managedRoleClaimKey            = "silo_role"
)

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
	authorizedContract string,
) (string, bool, error) {
	managed, err := managedRoleRequested(response)
	if err != nil || !managed {
		return "", false, err
	}
	claims := response.GetClaims().AsMap()
	if authorizedContract != ManagedRoleContractV1 {
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
	if response == nil || response.GetClaims() == nil {
		return false, nil
	}
	claims := response.GetClaims().AsMap()
	rawMarker, hasMarker := claims[managedRoleMarkerClaimKey]
	if !hasMarker {
		return false, nil
	}
	managed, ok := rawMarker.(bool)
	if !ok {
		return false, fmt.Errorf("plugin auth claim %q must be a boolean", managedRoleMarkerClaimKey)
	}
	return managed, nil
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
