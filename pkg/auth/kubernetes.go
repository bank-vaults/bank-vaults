package auth

import "time"

type KubernetesRole struct {
	// Policies that are to be required by the token to access this role
	Policies []string `json:"policies"`

	// Duration before which an issued token must be renewed
	TTL time.Duration `json:"ttl"`

	// Duration after which an issued token should not be allowed to be renewed
	MaxTTL time.Duration `json:"max_ttl"`

	// Period, if set, indicates that the token generated using this role
	// should never expire. The token should be renewed within the duration
	// specified by this value. The renewal duration will be fixed if the
	// value is not modified on the role. If the `Period` in the role is modified,
	// a token will pick up the new value during its next renewal.
	Period time.Duration `json:"period"`

	// ServiceAccountNames is the array of service accounts able to
	// access this role.
	ServiceAccountNames []string `json:"bound_service_account_names"`

	// ServiceAccountNamespaces is the array of namespaces able to access this
	// role.
	ServiceAccountNamespaces []string `json:"bound_service_account_namespaces"`
}
