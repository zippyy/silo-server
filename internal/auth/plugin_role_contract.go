package auth

import (
	"fmt"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

const (
	ManagedRoleContractV1 = "silo.auth.managed-role.v1"

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
	if _, ok := values["user"]; !ok {
		return "", fmt.Errorf("managed-role contract does not advertise user")
	}
	if _, ok := values["admin"]; !ok {
		return "", fmt.Errorf("managed-role contract does not advertise admin")
	}
	return contract, nil
}

func managedRoleFromResponse(
	response *pluginv1.AuthenticateResponse,
	authorizedContract string,
) (string, bool, error) {
	if response == nil || response.GetClaims() == nil {
		return "", false, nil
	}
	claims := response.GetClaims().AsMap()
	rawMarker, hasMarker := claims[managedRoleMarkerClaimKey]
	if !hasMarker {
		return "", false, nil
	}
	managed, ok := rawMarker.(bool)
	if !ok {
		return "", false, fmt.Errorf("plugin auth claim %q must be a boolean", managedRoleMarkerClaimKey)
	}
	if !managed {
		return "", false, nil
	}
	if authorizedContract != ManagedRoleContractV1 {
		return "", false, fmt.Errorf("plugin is not authorized for managed roles")
	}
	contract, ok := claims[managedRoleContractClaimKey].(string)
	if !ok || contract != ManagedRoleContractV1 {
		return "", false, fmt.Errorf("plugin managed-role response uses an unsupported contract")
	}
	role, ok := claims[managedRoleClaimKey].(string)
	if !ok || (role != "user" && role != "admin") {
		return "", false, fmt.Errorf("plugin managed-role response contains an unsupported role")
	}
	return role, true, nil
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
