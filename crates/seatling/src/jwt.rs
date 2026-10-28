use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const MAX_JWT_LEN: usize = 32 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl JwtHeader {
    pub fn new(typ: &str, kid: Option<&str>) -> Self {
        Self {
            alg: "EdDSA".to_string(),
            typ: typ.to_string(),
            kid: kid.map(|s| s.to_string()),
        }
    }
}

pub fn encode_eddsa_jwt<T: Serialize>(
    header: &JwtHeader,
    claims: &T,
    signing_key: &SigningKey,
) -> Result<String, String> {
    let header_json = serde_json::to_vec(header).map_err(|e| e.to_string())?;
    let claims_json = serde_json::to_vec(claims).map_err(|e| e.to_string())?;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json);

    let signing_input = format!("{}.{}", header_b64, claims_b64);
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{}.{}", signing_input, sig_b64))
}

pub fn decode_and_verify_jwt<T: DeserializeOwned, F>(
    token: &str,
    resolve_key: F,
) -> Result<(JwtHeader, T), String>
where
    F: FnOnce(&JwtHeader) -> Result<VerifyingKey, String>,
{
    let trimmed = token.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_JWT_LEN {
        return Err("Invalid JWT length".to_string());
    }
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format: expected 3 parts".to_string());
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| format!("Invalid base64url header: {}", e))?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("Invalid header JSON: {}", e))?;

    if header.alg != "EdDSA" {
        return Err(format!(
            "Unsupported algorithm: {}, expected EdDSA",
            header.alg
        ));
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("Invalid base64url signature: {}", e))?;
    if sig_bytes.len() != 64 {
        return Err("Invalid Ed25519 signature length (must be 64 bytes)".to_string());
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let verifying_key = resolve_key(&header)?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|e| format!("EdDSA signature verification failed: {}", e))?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("Invalid base64url claims: {}", e))?;
    let claims: T =
        serde_json::from_slice(&claims_bytes).map_err(|e| format!("Invalid claims JSON: {}", e))?;

    Ok((header, claims))
}
