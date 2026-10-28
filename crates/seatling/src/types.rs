use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(C)]
pub enum AttestationTier {
    HardwareSealed,
    Software,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub enum StatusCode {
    Ok = 0,
    OfflineGraceValid = 1,
    NotActivated = 2,
    OfflineGraceExpired = 3,
    SeatsExhausted = 4,
    RequiresPortalDeactivation = 5,
    LicenseSuspendedOrRevoked = 6,
    VersionCeilingExceeded = 7,
    TamperOrSignatureInvalid = 8,
    NetworkError = 9,
    TimeTamperDetected = 10,
    InvalidProductOrWorkspace = 11,
    KeyRevokedUpdateRequired = 12,
    InvalidConfiguration = 13,
}

impl StatusCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            StatusCode::Ok => "OK",
            StatusCode::OfflineGraceValid => "OFFLINE_GRACE_VALID",
            StatusCode::NotActivated => "NOT_ACTIVATED",
            StatusCode::OfflineGraceExpired => "OFFLINE_GRACE_EXPIRED",
            StatusCode::SeatsExhausted => "SEATS_EXHAUSTED",
            StatusCode::RequiresPortalDeactivation => "REQUIRES_PORTAL_DEACTIVATION",
            StatusCode::LicenseSuspendedOrRevoked => "LICENSE_SUSPENDED_OR_REVOKED",
            StatusCode::VersionCeilingExceeded => "VERSION_CEILING_EXCEEDED",
            StatusCode::TamperOrSignatureInvalid => "TAMPER_OR_SIGNATURE_INVALID",
            StatusCode::NetworkError => "NETWORK_ERROR",
            StatusCode::TimeTamperDetected => "TIME_TAMPER_DETECTED",
            StatusCode::InvalidProductOrWorkspace => "INVALID_PRODUCT_OR_WORKSPACE",
            StatusCode::KeyRevokedUpdateRequired => "KEY_REVOKED_UPDATE_REQUIRED",
            StatusCode::InvalidConfiguration => "INVALID_CONFIGURATION",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HWIDComponents {
    pub cpu: String,
    pub mobo: String,
    pub disk: String,
    pub os_uuid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeatlingConfig {
    pub workspace_id: String,
    pub product_id: String,
    pub public_keys: HashMap<String, String>, // Dedicated workspace Ed25519 public keys indexed by kid
    pub app_version: String,
    #[serde(default = "default_api_url")]
    pub api_base_url: String,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_seconds: u32,
    pub storage_dir: Option<String>,
}

fn default_api_url() -> String {
    "https://api.seatling.com".to_string()
}

fn default_heartbeat_interval() -> u32 {
    14400 // 4 hours
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseStatus {
    pub status: StatusCode,
    pub is_authorized: bool,
    pub seat_id: Option<String>,
    pub masked_key: Option<String>,
    pub buyer_email: Option<String>,
    pub last_verified_at_unix: Option<i64>,
    pub offline_expires_at_unix: Option<i64>,
    pub is_within_offline_grace: bool,
    pub portal_url: Option<String>,
    pub message: Option<String>,
    pub entitlements: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationResult {
    pub success: bool,
    pub status: StatusCode,
    pub message: String,
    pub seat_id: Option<String>,
    pub portal_url: Option<String>,
    pub buyer_email: Option<String>,
    pub seats_active: Option<i32>,
    pub seat_limit: Option<i32>,
    pub lease_status: Option<LeaseStatus>,
    pub token: Option<String>,
}

// Wire request/response wrapper for JWT exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangePayload {
    pub token: String,
}

// V6 JWT Claims: Client Activation Proof-of-Possession (typ: "seatling-activate-pop+jwt")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationPopClaims {
    pub iss: String, // Base64 device public key
    pub sub: String, // License key
    pub aud: String, // e.g. "https://api.seatling.com"
    pub hwid: String,
    pub hwid_components: HWIDComponents,
    pub app_version: String,
    pub attestation_tier: AttestationTier,
    pub supported_kids: Vec<String>,
    pub iat: i64,
    pub jti: String, // Nonce CSPRNG
}

// V6 JWT Claims: Server License Token (.seatling lease) (typ: "seatling-license+jwt")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseJwtClaims {
    pub iss: String,
    pub sub: String, // License key
    pub aud: String, // workspace_id
    pub product_id: String,
    pub seat_id: String,
    #[serde(default)]
    pub masked_key: Option<String>,
    #[serde(default)]
    pub buyer_email: Option<String>,
    pub hwid: String,
    #[serde(alias = "device_pubkey")]
    pub device_key: Option<String>,
    pub app_version: String,
    pub iat: i64,
    #[serde(default)]
    pub nbf: Option<i64>,
    pub exp: i64, // Offline grace expiration timestamp (iat + offline_grace_days * 86400)
    #[serde(default)]
    pub offline_grace_days: Option<i64>,
    #[serde(default = "default_active_status")]
    pub status: String,
    #[serde(default)]
    pub entitlements: HashMap<String, serde_json::Value>,
}

fn default_active_status() -> String {
    "active".to_string()
}

// V6 JWT Claims: Client Heartbeat Challenge (typ: "seatling-heartbeat-challenge+jwt")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatChallengeClaims {
    pub iss: String, // Base64 device public key
    pub sub: String, // License key
    pub aud: String, // e.g. "https://api.seatling.com"
    pub seat_id: String,
    pub hwid: String,
    pub session_id: String,
    pub app_version: String,
    pub supported_kids: Vec<String>,
    pub iat: i64,
    pub jti: String, // Nonce CSPRNG
}

// V5 JWT Claims: Server Heartbeat Acknowledgment (typ: "seatling-heartbeat-ack+jwt")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAckClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String, // workspace_id
    pub product_id: String,
    pub seat_id: String,
    pub status: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String, // Echoes client challenge nonce!
    #[serde(default)]
    pub entitlements: HashMap<String, serde_json::Value>,
}

// V7 JWT Claims: Client Deactivation (typ: "seatling-deactivate+jwt")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeactivationClaims {
    pub iss: String, // Base64 device public key
    pub sub: String, // License key
    pub seat_id: String,
    pub hwid: String,
    pub iat: i64,
    pub jti: String, // Nonce CSPRNG
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeystoreFile {
    pub version: u32,
    pub tier: AttestationTier,
    pub public_key: String,
    pub iv: String,
    pub auth_tag: String,
    pub ciphertext: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpapi_blob: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sw_secret: Option<String>,
}
