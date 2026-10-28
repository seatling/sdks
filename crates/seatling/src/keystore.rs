use crate::hwid::HWIDCollector;
use crate::jwt::{encode_eddsa_jwt, JwtHeader};
use crate::platform::SealingAnchors;
use crate::storage::StorageManager;
use crate::types::{
    ActivationPopClaims, AttestationTier, DeactivationClaims, HWIDComponents,
    HeartbeatChallengeClaims, StatusCode, StoredKeystoreFile,
};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::time::Duration;

const HKDF_SALT_V2: &[u8] = b"seatling:keystore:v2:salt";
const HKDF_INFO_V2: &[u8] = b"seatling:hardware_sealed_ed25519_key_v2";

pub const KEYSTORE_RECORD_V3_LEN: usize = 88;
pub const KEYSTORE_RECORD_V4_LEN: usize = 104;

#[inline]
pub fn zeroize_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// AES-256-GCM Encrypted Keystore Record (104 bytes total for V4)
/// ├── ed25519_private_key      (32 bytes)
/// ├── ed25519_public_key       (32 bytes)
/// ├── last_validated_at_utc    (int64 Unix epoch seconds, server-authenticated)
/// ├── grace_duration_seconds   (int64, from server-signed token)
/// ├── high_water_mark_utc      (int64 Unix epoch seconds, monotonic local clock)
/// ├── revocation_status        (uint32, 0 if clean, or persisted StatusCode)
/// ├── ack_state_tag            (uint32, 0 if no ack, or truncated SHA-256 of active ack)
/// └── revocation_context       (8 bytes, context hash for scoped revocations)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeystoreRecord {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub last_validated_at_utc: i64,
    pub grace_duration_seconds: i64,
    pub high_water_mark_utc: i64,
    pub revocation_status: u32,
    pub ack_state_tag: u32,
    pub revocation_context: [u8; 8],
}

impl Drop for KeystoreRecord {
    fn drop(&mut self) {
        zeroize_slice(&mut self.private_key);
    }
}

impl KeystoreRecord {
    pub fn to_bytes(&self) -> [u8; KEYSTORE_RECORD_V4_LEN] {
        let mut buf = [0u8; KEYSTORE_RECORD_V4_LEN];
        buf[0..32].copy_from_slice(&self.private_key);
        buf[32..64].copy_from_slice(&self.public_key);
        buf[64..72].copy_from_slice(&self.last_validated_at_utc.to_be_bytes());
        buf[72..80].copy_from_slice(&self.grace_duration_seconds.to_be_bytes());
        buf[80..88].copy_from_slice(&self.high_water_mark_utc.to_be_bytes());
        buf[88..92].copy_from_slice(&self.revocation_status.to_be_bytes());
        buf[92..96].copy_from_slice(&self.ack_state_tag.to_be_bytes());
        buf[96..104].copy_from_slice(&self.revocation_context);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != KEYSTORE_RECORD_V4_LEN && bytes.len() != KEYSTORE_RECORD_V3_LEN {
            return Err("Invalid keystore record length (expected 88 or 104 bytes)");
        }
        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        private_key.copy_from_slice(&bytes[0..32]);
        public_key.copy_from_slice(&bytes[32..64]);

        let mut b8 = [0u8; 8];
        b8.copy_from_slice(&bytes[64..72]);
        let last_validated_at_utc = i64::from_be_bytes(b8);

        b8.copy_from_slice(&bytes[72..80]);
        let grace_duration_seconds = i64::from_be_bytes(b8);

        b8.copy_from_slice(&bytes[80..88]);
        let high_water_mark_utc = i64::from_be_bytes(b8);

        let (revocation_status, ack_state_tag, revocation_context) =
            if bytes.len() == KEYSTORE_RECORD_V4_LEN {
                let mut b4 = [0u8; 4];
                b4.copy_from_slice(&bytes[88..92]);
                let status = u32::from_be_bytes(b4);
                b4.copy_from_slice(&bytes[92..96]);
                let ack_tag = u32::from_be_bytes(b4);
                let mut ctx = [0u8; 8];
                ctx.copy_from_slice(&bytes[96..104]);
                (status, ack_tag, ctx)
            } else {
                (0, 0, [0u8; 8])
            };

        Ok(Self {
            private_key,
            public_key,
            last_validated_at_utc,
            grace_duration_seconds,
            high_water_mark_utc,
            revocation_status,
            ack_state_tag,
            revocation_context,
        })
    }
}

pub struct HardwareSealedKeystore {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    tier: AttestationTier,
    record: KeystoreRecord,
}

impl HardwareSealedKeystore {
    pub fn load_or_generate(storage: &StorageManager) -> Self {
        let _lock = storage.acquire_lock(Duration::from_secs(3)).ok();
        Self::load_or_generate_unlocked(storage)
    }

    fn load_or_generate_unlocked(storage: &StorageManager) -> Self {
        let anchors = HWIDCollector::sealing_anchors();

        if let Some(content) = storage.read_keystore() {
            if let Ok(stored) = serde_json::from_str::<StoredKeystoreFile>(&content) {
                if stored.version == 2 {
                    if let Ok(keystore) = Self::try_unseal_v2(&stored, anchors, storage) {
                        return keystore;
                    }
                    // Failed to unseal v2 keystore
                    let unreadable_path = storage.get_dir().join("keystore.bin.unreadable");
                    let _ = std::fs::rename(storage.keystore_path(), unreadable_path);
                } else {
                    // Version != 2 (e.g. legacy v1). Per approved decision: clean break, rename to unreadable.
                    let unreadable_path = storage.get_dir().join("keystore.bin.unreadable");
                    let _ = std::fs::rename(storage.keystore_path(), unreadable_path);
                }
            }
        }

        // Generate fresh keypair
        let mut seed = [0u8; 32];
        rand::fill(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let now_utc = Self::current_unix_time();

        let record = KeystoreRecord {
            private_key: seed,
            public_key: *verifying_key.as_bytes(),
            last_validated_at_utc: now_utc,
            grace_duration_seconds: 0, // Clean keystore grants 0 offline grace until first activation
            high_water_mark_utc: now_utc,
            revocation_status: 0,
            ack_state_tag: 0,
            revocation_context: [0u8; 8],
        };
        zeroize_slice(&mut seed);

        let tier = if anchors.is_hardware_rooted() {
            AttestationTier::HardwareSealed
        } else {
            AttestationTier::Software
        };

        let instance = Self {
            signing_key,
            verifying_key,
            tier,
            record,
        };

        instance.persist(storage);
        instance
    }

    fn try_unseal_v2(
        stored: &StoredKeystoreFile,
        anchors: &SealingAnchors,
        storage: &StorageManager,
    ) -> Result<Self, &'static str> {
        let current_anchor = storage.read_secret_anchor();
        match Self::try_unseal_v2_internal(stored, anchors, current_anchor) {
            Ok(ks) => Ok(ks),
            Err(e) => {
                if let Some(prev_anchor) = storage.read_secret_anchor_prev() {
                    if let Ok(ks) = Self::try_unseal_v2_internal(stored, anchors, Some(prev_anchor))
                    {
                        storage.restore_secret_anchor_backup();
                        return Ok(ks);
                    }
                }
                Err(e)
            }
        }
    }

    fn try_unseal_v2_internal(
        stored: &StoredKeystoreFile,
        anchors: &SealingAnchors,
        anchor_opt: Option<[u8; 32]>,
    ) -> Result<Self, &'static str> {
        let iv = BASE64.decode(&stored.iv).map_err(|_| "invalid iv")?;
        let ct = BASE64
            .decode(&stored.ciphertext)
            .map_err(|_| "invalid ct")?;
        let tag = BASE64.decode(&stored.auth_tag).map_err(|_| "invalid tag")?;

        if iv.len() != 12 || tag.len() != 16 {
            return Err("invalid dimensions");
        }

        let mut secret32 = [0u8; 32];
        #[cfg(target_os = "windows")]
        {
            if stored.tier == AttestationTier::HardwareSealed {
                if let Some(ref dpapi_b64) = stored.dpapi_blob {
                    let dpapi_bytes = BASE64.decode(dpapi_b64).map_err(|_| "invalid dpapi")?;
                    let mut unprotected = dpapi_unprotect(&dpapi_bytes, b"seatling:dpapi:v2")
                        .map_err(|_| "dpapi unprotect failed")?;
                    if unprotected.len() != 32 {
                        zeroize_slice(&mut unprotected);
                        return Err("invalid secret len");
                    }
                    secret32.copy_from_slice(&unprotected);
                    zeroize_slice(&mut unprotected);
                    if let Some(mut anchor) = anchor_opt {
                        for (s, a) in secret32.iter_mut().zip(anchor.iter()) {
                            *s ^= *a;
                        }
                        zeroize_slice(&mut anchor);
                    }
                } else {
                    return Err("missing dpapi blob");
                }
            } else if let Some(mut anchor) = anchor_opt {
                secret32.copy_from_slice(&anchor);
                zeroize_slice(&mut anchor);
            } else if let Some(ref sw_b64) = stored.sw_secret {
                let sw_bytes = BASE64.decode(sw_b64).map_err(|_| "invalid sw_secret")?;
                if sw_bytes.len() != 32 {
                    return Err("invalid sw len");
                }
                secret32.copy_from_slice(&sw_bytes);
            } else {
                return Err("missing keystore secret anchor");
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            if let Some(mut anchor) = anchor_opt {
                secret32.copy_from_slice(&anchor);
                zeroize_slice(&mut anchor);
            } else if let Some(ref sw_b64) = stored.sw_secret {
                let sw_bytes = BASE64.decode(sw_b64).map_err(|_| "invalid sw_secret")?;
                if sw_bytes.len() != 32 {
                    return Err("invalid sw len");
                }
                secret32.copy_from_slice(&sw_bytes);
            } else {
                return Err("missing keystore secret anchor");
            }
        }

        let mut wrapping_key = Self::derive_wrapping_key_v2(&secret32, anchors, stored.tier);
        zeroize_slice(&mut secret32);

        let cipher = Aes256Gcm::new_from_slice(&wrapping_key).map_err(|_| "cipher error")?;
        zeroize_slice(&mut wrapping_key);

        let mut combined = ct;
        combined.extend_from_slice(&tag);

        let aad = Self::build_aad(stored.version, stored.tier, &stored.public_key);
        let payload = Payload {
            msg: &combined,
            aad: &aad,
        };

        let nonce = Nonce::try_from(iv.as_slice()).map_err(|_| "invalid nonce")?;
        let mut decrypted = cipher
            .decrypt(&nonce, payload)
            .map_err(|_| "decrypt failed")?;

        let res = KeystoreRecord::from_bytes(&decrypted);
        zeroize_slice(&mut decrypted);
        let record = res?;

        let signing_key = SigningKey::from_bytes(&record.private_key);
        let verifying_key = signing_key.verifying_key();
        if record.public_key != *verifying_key.as_bytes() {
            return Err("pubkey mismatch");
        }

        Ok(Self {
            signing_key,
            verifying_key,
            tier: stored.tier,
            record,
        })
    }

    pub fn record(&self) -> &KeystoreRecord {
        &self.record
    }

    pub fn evaluate_clock_and_grace(&self, system_utc_time: i64) -> StatusCode {
        if system_utc_time < self.record.high_water_mark_utc.saturating_sub(300) {
            return StatusCode::TimeTamperDetected;
        }

        let effective_time = system_utc_time.max(self.record.high_water_mark_utc);
        let expires_at = self
            .record
            .last_validated_at_utc
            .saturating_add(self.record.grace_duration_seconds.max(0));
        if effective_time > expires_at {
            return StatusCode::OfflineGraceExpired;
        }

        StatusCode::Ok
    }

    pub fn advance_high_water_mark(&mut self, storage: &StorageManager, system_utc_time: i64) {
        if system_utc_time > self.record.high_water_mark_utc {
            self.mutate(storage, |rec| {
                if system_utc_time > rec.high_water_mark_utc {
                    rec.high_water_mark_utc = system_utc_time;
                }
            });
        }
    }

    pub fn update_timeline(
        &mut self,
        storage: &StorageManager,
        server_timestamp_utc: i64,
        grace_duration_seconds: i64,
    ) {
        self.mutate(storage, |rec| {
            rec.last_validated_at_utc = server_timestamp_utc;
            rec.high_water_mark_utc = server_timestamp_utc;
            rec.grace_duration_seconds = grace_duration_seconds.max(0);
            rec.revocation_status = 0;
            rec.revocation_context = [0u8; 8];
        });
    }

    pub fn rotate_keypair(&mut self, storage: &StorageManager) {
        let _lock = storage.acquire_lock(Duration::from_secs(3)).ok();
        let mut seed = [0u8; 32];
        rand::fill(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let now_utc = Self::current_unix_time();

        self.signing_key = signing_key;
        self.verifying_key = verifying_key;
        self.record.private_key = seed;
        self.record.public_key = *verifying_key.as_bytes();
        self.record.last_validated_at_utc = now_utc;
        self.record.grace_duration_seconds = 0;
        self.record.high_water_mark_utc = self.record.high_water_mark_utc.max(now_utc);
        self.record.revocation_status = 0;
        self.record.ack_state_tag = 0;
        self.record.revocation_context = [0u8; 8];
        zeroize_slice(&mut seed);

        self.persist(storage);
    }

    pub fn mutate<F>(&mut self, storage: &StorageManager, f: F)
    where
        F: FnOnce(&mut KeystoreRecord),
    {
        let _lock = storage.acquire_lock(Duration::from_secs(3)).ok();
        // Reload record from disk if possible to synchronize cross-process changes
        let anchors = HWIDCollector::sealing_anchors();
        if let Some(content) = storage.read_keystore() {
            if let Ok(stored) = serde_json::from_str::<StoredKeystoreFile>(&content) {
                if let Ok(ks) = Self::try_unseal_v2(&stored, anchors, storage) {
                    if ks.verifying_key == self.verifying_key {
                        self.record = ks.record;
                    }
                }
            }
        }

        f(&mut self.record);
        self.persist(storage);
    }

    pub fn persist(&self, storage: &StorageManager) {
        let anchors = HWIDCollector::sealing_anchors();

        let mut secret32 = [0u8; 32];
        rand::fill(&mut secret32);

        #[allow(unused_mut)]
        let mut dpapi_blob = None;
        let sw_secret = None;

        storage.backup_secret_anchor();

        #[cfg(target_os = "windows")]
        {
            if self.tier == AttestationTier::HardwareSealed {
                if let Ok(protected) = dpapi_protect(&secret32, b"seatling:dpapi:v2") {
                    dpapi_blob = Some(BASE64.encode(protected));
                }
                let mut anchor = [0u8; 32];
                rand::fill(&mut anchor);
                if storage.write_secret_anchor(&anchor).is_ok() {
                    for (s, a) in secret32.iter_mut().zip(anchor.iter()) {
                        *s ^= *a;
                    }
                }
                zeroize_slice(&mut anchor);
            } else {
                let _ = storage.write_secret_anchor(&secret32);
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = storage.write_secret_anchor(&secret32);
        }

        let mut wrapping_key = Self::derive_wrapping_key_v2(&secret32, anchors, self.tier);
        zeroize_slice(&mut secret32);

        let Ok(cipher) = Aes256Gcm::new_from_slice(&wrapping_key) else {
            zeroize_slice(&mut wrapping_key);
            storage.cleanup_secret_anchor_backup();
            return;
        };
        zeroize_slice(&mut wrapping_key);

        let mut iv = [0u8; 12];
        rand::fill(&mut iv);
        let nonce = Nonce::from(iv);

        let mut raw_record = self.record.to_bytes();
        let pub_key_b64 = BASE64.encode(self.verifying_key.as_bytes());
        let aad = Self::build_aad(2, self.tier, &pub_key_b64);

        let payload = Payload {
            msg: raw_record.as_ref(),
            aad: &aad,
        };

        let encrypted = cipher.encrypt(&nonce, payload);
        zeroize_slice(&mut raw_record);

        if let Ok(ciphertext_with_tag) = encrypted {
            let split_pos = ciphertext_with_tag.len().saturating_sub(16);
            let ciphertext = &ciphertext_with_tag[..split_pos];
            let tag = &ciphertext_with_tag[split_pos..];

            let stored = StoredKeystoreFile {
                version: 2,
                tier: self.tier,
                public_key: pub_key_b64,
                iv: BASE64.encode(iv),
                auth_tag: BASE64.encode(tag),
                ciphertext: BASE64.encode(ciphertext),
                dpapi_blob,
                sw_secret,
            };

            if let Ok(json) = serde_json::to_string_pretty(&stored) {
                let _ = storage.write_keystore(&json);
            }
        }

        storage.cleanup_secret_anchor_backup();
    }

    fn build_aad(version: u32, tier: AttestationTier, public_key: &str) -> Vec<u8> {
        let tier_byte = match tier {
            AttestationTier::HardwareSealed => 1u8,
            AttestationTier::Software => 0u8,
        };
        let mut aad = Vec::new();
        aad.extend_from_slice(&version.to_be_bytes());
        aad.push(tier_byte);
        aad.extend_from_slice(public_key.as_bytes());
        aad
    }

    pub fn derive_wrapping_key_v2(
        secret: &[u8; 32],
        anchors: &SealingAnchors,
        tier: AttestationTier,
    ) -> [u8; 32] {
        let mut ikm = Vec::new();
        ikm.extend_from_slice(b"seatling:v2");
        ikm.push(match tier {
            AttestationTier::HardwareSealed => 1,
            AttestationTier::Software => 0,
        });
        ikm.extend_from_slice(secret);

        let mut sorted_hw = anchors.hardware.clone();
        sorted_hw.sort_by_key(|(k, _)| *k);

        for (k, v) in sorted_hw {
            ikm.extend_from_slice(k.as_bytes());
            ikm.push(b'=');
            ikm.extend_from_slice(v.as_bytes());
            ikm.push(b';');
        }

        if let Some(ref u) = anchors.user_scope {
            ikm.extend_from_slice(b"user=");
            ikm.extend_from_slice(u.as_bytes());
        }

        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT_V2), &ikm);
        let mut okm = [0u8; 32];
        hkdf.expand(HKDF_INFO_V2, &mut okm)
            .expect("32 bytes is valid length for HKDF-SHA256");
        okm
    }

    fn current_unix_time() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.verifying_key.as_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    pub fn attestation_tier(&self) -> AttestationTier {
        self.tier
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_activation_pop_jwt(
        &self,
        key: &str,
        hwid: &str,
        hwid_components: HWIDComponents,
        app_version: &str,
        aud: &str,
        supported_kids: &[String],
        timestamp: i64,
        nonce: &str,
    ) -> Result<String, String> {
        let header = JwtHeader::new("seatling-activate-pop+jwt", None);
        let claims = ActivationPopClaims {
            iss: self.public_key_base64(),
            sub: key.to_string(),
            aud: aud.to_string(),
            hwid: hwid.to_string(),
            hwid_components,
            app_version: app_version.to_string(),
            attestation_tier: self.tier,
            supported_kids: supported_kids.to_vec(),
            iat: timestamp,
            jti: nonce.to_string(),
        };
        encode_eddsa_jwt(&header, &claims, &self.signing_key)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_heartbeat_challenge_jwt(
        &self,
        key: &str,
        seat_id: &str,
        hwid: &str,
        session_id: &str,
        app_version: &str,
        aud: &str,
        supported_kids: &[String],
        timestamp: i64,
        nonce: &str,
    ) -> Result<String, String> {
        let header = JwtHeader::new("seatling-heartbeat-challenge+jwt", None);
        let claims = HeartbeatChallengeClaims {
            iss: self.public_key_base64(),
            sub: key.to_string(),
            aud: aud.to_string(),
            seat_id: seat_id.to_string(),
            hwid: hwid.to_string(),
            session_id: session_id.to_string(),
            app_version: app_version.to_string(),
            supported_kids: supported_kids.to_vec(),
            iat: timestamp,
            jti: nonce.to_string(),
        };
        encode_eddsa_jwt(&header, &claims, &self.signing_key)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_activation_proof(
        &self,
        key: &str,
        hwid: &str,
        hwid_components: HWIDComponents,
        app_version: &str,
        aud: &str,
        supported_kids: &[String],
        timestamp: i64,
        nonce: &str,
    ) -> String {
        self.sign_activation_pop_jwt(
            key,
            hwid,
            hwid_components,
            app_version,
            aud,
            supported_kids,
            timestamp,
            nonce,
        )
        .unwrap_or_default()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_heartbeat(
        &self,
        key: &str,
        seat_id: &str,
        hwid: &str,
        session_id: &str,
        app_version: &str,
        aud: &str,
        supported_kids: &[String],
        nonce: &str,
        timestamp: i64,
    ) -> String {
        self.sign_heartbeat_challenge_jwt(
            key,
            seat_id,
            hwid,
            session_id,
            app_version,
            aud,
            supported_kids,
            timestamp,
            nonce,
        )
        .unwrap_or_default()
    }

    pub fn sign_deactivation(
        &self,
        key: &str,
        seat_id: &str,
        hwid: &str,
        nonce: &str,
        timestamp: i64,
    ) -> String {
        let header = JwtHeader::new("seatling-deactivate+jwt", None);
        let claims = DeactivationClaims {
            iss: self.public_key_base64(),
            sub: key.to_string(),
            seat_id: seat_id.to_string(),
            hwid: hwid.to_string(),
            iat: timestamp,
            jti: nonce.to_string(),
        };
        encode_eddsa_jwt(&header, &claims, &self.signing_key).unwrap_or_default()
    }
}

#[cfg(target_os = "windows")]
fn dpapi_protect(secret: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(hmem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    let data_in = CRYPT_INTEGER_BLOB {
        cbData: secret.len() as u32,
        pbData: secret.as_ptr() as *mut u8,
    };
    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };

    unsafe {
        let ok = CryptProtectData(
            &data_in,
            std::ptr::null(),
            &entropy_blob,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        );
        if ok == 0 || data_out.pbData.is_null() {
            return Err("CryptProtectData failed".to_string());
        }
        let slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
        let result = slice.to_vec();
        std::ptr::write_bytes(data_out.pbData, 0, data_out.cbData as usize);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        LocalFree(data_out.pbData as *mut _);
        Ok(result)
    }
}

#[cfg(target_os = "windows")]
fn dpapi_unprotect(ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(hmem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    let data_in = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };

    unsafe {
        let ok = CryptUnprotectData(
            &data_in,
            std::ptr::null_mut(),
            &entropy_blob,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        );
        if ok == 0 || data_out.pbData.is_null() {
            return Err("CryptUnprotectData failed".to_string());
        }
        let slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
        let result = slice.to_vec();
        std::ptr::write_bytes(data_out.pbData, 0, data_out.cbData as usize);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        LocalFree(data_out.pbData as *mut _);
        Ok(result)
    }
}
