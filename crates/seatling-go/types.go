package seatling

import (
	"fmt"
)

// StatusCode matches the authoritative seatling_status_code_t enumeration from the Rust core.
type StatusCode uint32

const (
	StatusOk                         StatusCode = 0
	StatusOfflineGraceValid          StatusCode = 1
	StatusNotActivated               StatusCode = 2
	StatusOfflineGraceExpired        StatusCode = 3
	StatusSeatsExhausted             StatusCode = 4
	StatusRequiresPortalDeactivation StatusCode = 5
	StatusLicenseSuspendedOrRevoked  StatusCode = 6
	StatusVersionCeilingExceeded     StatusCode = 7
	StatusTamperOrSignatureInvalid   StatusCode = 8
	StatusNetworkError               StatusCode = 9
	StatusTimeTamperDetected         StatusCode = 10
	StatusInvalidProductOrWorkspace  StatusCode = 11
	StatusKeyRevokedUpdateRequired   StatusCode = 12
	StatusInvalidConfiguration       StatusCode = 13
)

func (s StatusCode) String() string {
	switch s {
	case StatusOk:
		return "SEATLING_STATUS_OK"
	case StatusOfflineGraceValid:
		return "SEATLING_STATUS_OFFLINE_GRACE_VALID"
	case StatusNotActivated:
		return "SEATLING_STATUS_NOT_ACTIVATED"
	case StatusOfflineGraceExpired:
		return "SEATLING_STATUS_OFFLINE_GRACE_EXPIRED"
	case StatusSeatsExhausted:
		return "SEATLING_STATUS_SEATS_EXHAUSTED"
	case StatusRequiresPortalDeactivation:
		return "SEATLING_STATUS_REQUIRES_PORTAL_DEACTIVATION"
	case StatusLicenseSuspendedOrRevoked:
		return "SEATLING_STATUS_LICENSE_SUSPENDED_OR_REVOKED"
	case StatusVersionCeilingExceeded:
		return "SEATLING_STATUS_VERSION_CEILING_EXCEEDED"
	case StatusTamperOrSignatureInvalid:
		return "SEATLING_STATUS_TAMPER_OR_SIGNATURE_INVALID"
	case StatusNetworkError:
		return "SEATLING_STATUS_NETWORK_ERROR"
	case StatusTimeTamperDetected:
		return "SEATLING_STATUS_TIME_TAMPER_DETECTED"
	case StatusInvalidProductOrWorkspace:
		return "SEATLING_STATUS_INVALID_PRODUCT_OR_WORKSPACE"
	case StatusKeyRevokedUpdateRequired:
		return "SEATLING_STATUS_KEY_REVOKED_UPDATE_REQUIRED"
	case StatusInvalidConfiguration:
		return "SEATLING_STATUS_INVALID_CONFIGURATION"
	default:
		return fmt.Sprintf("SEATLING_STATUS_UNKNOWN(%d)", uint32(s))
	}
}

// Config specifies initialization options for the Seatling licensing client.
type Config struct {
	// WorkspaceID is the unique workspace identifier (e.g. "ws_..."). Required.
	WorkspaceID string

	// ProductID is the unique product identifier (e.g. "prod_..."). Required.
	ProductID string

	// PublicKeys is a mapping of Key IDs (kid) to Base64 or Base64URL-encoded Ed25519 public keys.
	// Required; client initialization fails if empty.
	PublicKeys map[string]string

	// AppVersion is the semantic version string of the host application (defaults to "1.0.0").
	AppVersion string

	// APIBaseURL is the authoritative Seatling licensing API URL (defaults to "https://api.seatling.com").
	APIBaseURL string

	// HeartbeatIntervalSeconds is the background heartbeat interval (defaults to 14400 / 4 hours).
	HeartbeatIntervalSeconds uint32

	// StorageDir overrides the persistent offline storage directory. If empty, the platform-standard path is used.
	StorageDir string
}

// HWIDComponents contains individual hardware identifier components for fuzzy quorum calculations.
type HWIDComponents struct {
	CPU    string
	Mobo   string
	Disk   string
	OSUUID string
}
