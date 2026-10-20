use crate::jwt::{decode_and_verify_jwt, JwtHeader};
use crate::types::{HeartbeatAckClaims, LicenseJwtClaims, StatusCode};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TokenVerifier {
    workspace_keys: HashMap<String, VerifyingKey>,
}

impl TokenVerifier {
    pub fn new(keys_map: &HashMap<String, String>) -> Result<Self, crate::error::SeatlingError> {
        if keys_map.is_empty() {
            return Err(crate::error::SeatlingError::new(
                StatusCode::TamperOrSignatureInvalid,
                "At least one public key must be provided in public_keys",
            ));
        }

        let mut workspace_keys = HashMap::new();
        for (kid, key_b64) in keys_map {
            let vk = Self::parse_verifying_key_base64(key_b64).map_err(|e| {
                crate::error::SeatlingError::new(StatusCode::TamperOrSignatureInvalid, e)
            })?;
            workspace_keys.insert(kid.clone(), vk);
        }

        Ok(Self { workspace_keys })
    }

    pub fn from_keys_map(
        map: HashMap<String, String>,
    ) -> Result<Self, crate::error::SeatlingError> {
        Self::new(&map)
    }

    pub fn parse_verifying_key_base64(b64: &str) -> Result<VerifyingKey, String> {
        let trimmed = b64.trim();
        let key_bytes = URL_SAFE_NO_PAD
            .decode(trimmed)
            .or_else(|_| URL_SAFE.decode(trimmed))
            .or_else(|_| STANDARD.decode(trimmed))
            .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
            .map_err(|e| format!("Invalid base64/base64url public key: {}", e))?;

        if key_bytes.len() != 32 {
            return Err(format!(
                "Public key must be 32 bytes, got {}",
                key_bytes.len()
            ));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);

        VerifyingKey::from_bytes(&arr).map_err(|e| format!("Invalid Ed25519 public key: {}", e))
    }

    pub fn resolve_key(&self, header: &JwtHeader) -> Result<VerifyingKey, String> {
        if let Some(ref kid) = header.kid {
            if let Some(k) = self.workspace_keys.get(kid) {
                return Ok(*k);
            }
            return Err(format!("Unrecognized key id (kid): {}", kid));
        }

        Err("JWT header missing required 'kid'".to_string())
    }

    pub fn verify_license_token(
        &self,
        token_str: &str,
        expected_workspace_id: &str,
        expected_product_id: &str,
    ) -> Result<LicenseJwtClaims, (StatusCode, String)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.verify_license_token_at(token_str, expected_workspace_id, expected_product_id, now)
    }

    pub fn verify_license_token_at(
        &self,
        token_str: &str,
        expected_workspace_id: &str,
        expected_product_id: &str,
        now_unix: i64,
    ) -> Result<LicenseJwtClaims, (StatusCode, String)> {
        let (header, claims) =
            decode_and_verify_jwt::<LicenseJwtClaims, _>(token_str, |h| self.resolve_key(h))
                .map_err(|e| (StatusCode::TamperOrSignatureInvalid, e))?;

        if header.typ != "seatling-license+jwt" {
            return Err((
                StatusCode::TamperOrSignatureInvalid,
                format!(
                    "Unexpected JWT typ: {}, expected seatling-license+jwt",
                    header.typ
                ),
            ));
        }

        if claims.aud != expected_workspace_id || claims.product_id != expected_product_id {
            return Err((
                StatusCode::InvalidProductOrWorkspace,
                format!(
                    "Token audience/product claim mismatch: aud={}, product_id={}. Expected ws={}, prod={}",
                    claims.aud, claims.product_id, expected_workspace_id, expected_product_id
                ),
            ));
        }

        if claims.status != "active" {
            return Err((
                StatusCode::LicenseSuspendedOrRevoked,
                format!(
                    "License token status is '{}', expected 'active'",
                    claims.status
                ),
            ));
        }

        // Validity window checks with 300s clock skew tolerance
        if let Some(nbf) = claims.nbf {
            if nbf > now_unix.saturating_add(300) {
                return Err((
                    StatusCode::TamperOrSignatureInvalid,
                    "Token not valid yet (nbf in future)".to_string(),
                ));
            }
        }

        if claims.iat > now_unix.saturating_add(300) {
            return Err((
                StatusCode::TamperOrSignatureInvalid,
                "Token issued in future (iat exceeds clock skew tolerance)".to_string(),
            ));
        }

        if claims.exp < claims.iat {
            return Err((
                StatusCode::TamperOrSignatureInvalid,
                "Token expiration timestamp precedes issued_at".to_string(),
            ));
        }

        Ok(claims)
    }

    pub fn verify_license_token_bound(
        &self,
        token_str: &str,
        expected_workspace_id: &str,
        expected_product_id: &str,
        expected_hwid: &str,
        expected_device_pubkey: &VerifyingKey,
    ) -> Result<LicenseJwtClaims, (StatusCode, String)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.verify_license_token_bound_at(
            token_str,
            expected_workspace_id,
            expected_product_id,
            expected_hwid,
            expected_device_pubkey,
            now,
        )
    }

    pub fn verify_license_token_bound_at(
        &self,
        token_str: &str,
        expected_workspace_id: &str,
        expected_product_id: &str,
        expected_hwid: &str,
        expected_device_pubkey: &VerifyingKey,
        now_unix: i64,
    ) -> Result<LicenseJwtClaims, (StatusCode, String)> {
        let claims = self.verify_license_token_at(
            token_str,
            expected_workspace_id,
            expected_product_id,
            now_unix,
        )?;

        if !constant_time_eq(claims.hwid.as_bytes(), expected_hwid.as_bytes()) {
            return Err((
                StatusCode::TamperOrSignatureInvalid,
                "License token HWID does not match current device".to_string(),
            ));
        }

        // Mandatory device_key per HARDWARE_ANCHOR_V7 §7.4.2.3
        match claims.device_key {
            Some(ref dev_key_b64) if !dev_key_b64.trim().is_empty() => {
                let token_vk = Self::parse_verifying_key_base64(dev_key_b64).map_err(|e| {
                    (
                        StatusCode::TamperOrSignatureInvalid,
                        format!("Invalid device_key in license token: {}", e),
                    )
                })?;
                if token_vk != *expected_device_pubkey {
                    return Err((
                        StatusCode::TamperOrSignatureInvalid,
                        "License token device_key does not match hardware-sealed keystore"
                            .to_string(),
                    ));
                }
            }
            _ => {
                return Err((
                    StatusCode::TamperOrSignatureInvalid,
                    "License token missing mandatory device_key claim".to_string(),
                ));
            }
        }

        Ok(claims)
    }

    pub fn verify_heartbeat_ack_token(
        &self,
        token_str: &str,
        expected_nonce: &str,
        expected_workspace_id: &str,
        expected_product_id: &str,
        expected_sub: &str,
        expected_seat_id: &str,
    ) -> Result<HeartbeatAckClaims, (StatusCode, String)> {
        let (header, claims) =
            decode_and_verify_jwt::<HeartbeatAckClaims, _>(token_str, |h| self.resolve_key(h))
                .map_err(|e| (StatusCode::TamperOrSignatureInvalid, e))?;

        if header.typ != "seatling-heartbeat-ack+jwt" {
            return Err((
                StatusCode::TamperOrSignatureInvalid,
                format!(
                    "Unexpected JWT typ: {}, expected seatling-heartbeat-ack+jwt",
                    header.typ
                ),
            ));
        }

        if !constant_time_eq(claims.jti.as_bytes(), expected_nonce.as_bytes()) {
            return Err((
                StatusCode::TamperOrSignatureInvalid,
                format!(
                    "Heartbeat nonce mismatch: expected {}, got {}",
                    expected_nonce, claims.jti
                ),
            ));
        }

        if claims.aud != expected_workspace_id || claims.product_id != expected_product_id {
            return Err((
                StatusCode::InvalidProductOrWorkspace,
                format!(
                    "Heartbeat ack audience/product claim mismatch: aud={}, product_id={}",
                    claims.aud, claims.product_id
                ),
            ));
        }

        if !constant_time_eq(claims.sub.as_bytes(), expected_sub.as_bytes()) {
            return Err((
                StatusCode::TamperOrSignatureInvalid,
                "Heartbeat ack license subject mismatch".to_string(),
            ));
        }

        if !constant_time_eq(claims.seat_id.as_bytes(), expected_seat_id.as_bytes()) {
            return Err((
                StatusCode::TamperOrSignatureInvalid,
                "Heartbeat ack seat_id mismatch".to_string(),
            ));
        }

        if claims.exp < claims.iat {
            return Err((
                StatusCode::TamperOrSignatureInvalid,
                "Heartbeat ack expiration precedes issued_at".to_string(),
            ));
        }

        Ok(claims)
    }

    pub fn is_within_offline_grace(&self, exp_timestamp: i64) -> (bool, i64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        (now <= exp_timestamp, exp_timestamp)
    }
}

#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
