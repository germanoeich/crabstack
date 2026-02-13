package types

const VersionV1 = "v1"

type ComponentType string

const (
	ComponentTypeListener   ComponentType = "listener"
	ComponentTypeGateway    ComponentType = "gateway"
	ComponentTypeSubscriber ComponentType = "subscriber"
	ComponentTypeCron       ComponentType = "cron"
	ComponentTypeToolHost   ComponentType = "tool_host"
	ComponentTypeOperator   ComponentType = "operator"
	ComponentTypeProvider   ComponentType = "provider"
)

type TransportType string

const (
	TransportTypeUnixSocket TransportType = "unix_socket"
	TransportTypeHTTP       TransportType = "http"
	TransportTypeWS         TransportType = "ws"
	TransportTypeMTLSHTTP   TransportType = "mtls_http"
	TransportTypeMTLSWS     TransportType = "mtls_ws"
	TransportTypeInternal   TransportType = "internal"
)

type ProviderAuthState string

const (
	ProviderAuthStateValid          ProviderAuthState = "valid"
	ProviderAuthStateExpiring       ProviderAuthState = "expiring"
	ProviderAuthStateReauthRequired ProviderAuthState = "reauth_required"
)
