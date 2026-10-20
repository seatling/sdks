use crate::cache::{LeaseSnapshot, StateAndEntitlementCache};
use crate::error::SeatlingError;
use crate::hwid::HWIDCollector;
use crate::keystore::HardwareSealedKeystore;
use crate::storage::StorageManager;
use crate::types::{ActivationResult, LeaseStatus, LicenseJwtClaims, SeatlingConfig, StatusCode};
use crate::verifier::TokenVerifier;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct SeatlingClient {
    config: SeatlingConfig,
    storage: StorageManager,
    keystore: Arc<Mutex<HardwareSealedKeystore>>,
    verifier: TokenVerifier,
    cache: Arc<StateAndEntitlementCache>,
    worker_stop: Arc<(Mutex<bool>, Condvar)>,
    worker_handle: parking_lot_or_mutex_handle::WorkerHandle,
    session_id: String,
    supported_kids: Vec<String>,
    time_source: Option<Arc<dyn Fn() -> i64 + Send + Sync>>,
}

mod parking_lot_or_mutex_handle {
    use std::sync::Mutex;
    use std::thread::JoinHandle;

    pub struct WorkerHandle(pub Mutex<Option<JoinHandle<()>>>);
}

#[derive(Debug, PartialEq, Eq)]
enum LocalHint {
    Clean,
    RebindRequired,
    RevocationPersisted(StatusCode),
}

fn validate_semver(v: &str) -> bool {
    let parts: Vec<&str> = v.trim().split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    for part in parts {
        let clean = part.split('-').next().unwrap_or(part);
        if clean.is_empty() || !clean.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    true
}

impl SeatlingClient {
    pub fn new(config: SeatlingConfig) -> Result<Self, SeatlingError> {
        if !validate_semver(&config.app_version) {
            return Err(SeatlingError::new(
                StatusCode::InvalidConfiguration,
                format!(
                    "Invalid app_version: '{}' is not valid SemVer",
                    config.app_version
                ),
            ));
        }

        let storage = StorageManager::new(
            &config.workspace_id,
            &config.product_id,
            config.storage_dir.as_deref(),
        );

        let keystore = HardwareSealedKeystore::load_or_generate(&storage);
        let verifier = TokenVerifier::new(&config.public_keys)?;
        let cache = Arc::new(StateAndEntitlementCache::new());
        let worker_stop = Arc::new((Mutex::new(false), Condvar::new()));

        let mut session_bytes = [0u8; 16];
        rand::fill(&mut session_bytes);
        let session_id = hex::encode(session_bytes);

        let mut supported_kids: Vec<String> = config.public_keys.keys().cloned().collect();
        supported_kids.sort();

        Ok(Self {
            config,
            storage,
            keystore: Arc::new(Mutex::new(keystore)),
            verifier,
            cache,
            worker_stop,
            worker_handle: parking_lot_or_mutex_handle::WorkerHandle(Mutex::new(None)),
            session_id,
            supported_kids,
            time_source: None,
        })
    }

    pub fn with_time_source(mut self, ts: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        self.time_source = Some(ts);
        self
    }

    pub fn init(config: SeatlingConfig) -> Result<Self, SeatlingError> {
        let client = Self::new(config)?;
        client.initialize();
        Ok(client)
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    fn now_unix(&self) -> i64 {
        if let Some(ref ts) = self.time_source {
            ts()
        } else {
            Self::current_unix_time()
        }
    }

    pub fn compute_app_fingerprint(app_version: &str, supported_kids: &[String]) -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(app_version.as_bytes());
        for k in supported_kids {
            hasher.update(k.as_bytes());
        }
        let out = hasher.finalize();
        let mut res = [0u8; 8];
        res.copy_from_slice(&out[..8]);
        res
    }

    fn evaluate_local(&self, now_utc: i64) -> (LeaseSnapshot, LocalHint, Option<LicenseJwtClaims>) {
        let raw_token = match self.storage.read_lease() {
            Some(t) => t,
            None => {
                return (
                    LeaseSnapshot {
                        status: StatusCode::NotActivated,
                        is_authorized: false,
                        ..Default::default()
                    },
                    LocalHint::Clean,
                    None,
                );
            }
        };

        let current_hwid = HWIDCollector::get_hwid();
        let (mut clock_status, device_vk, rev_status, rev_context) = {
            let ks = self.keystore.lock().unwrap_or_else(|e| e.into_inner());
            (
                ks.evaluate_clock_and_grace(now_utc),
                ks.verifying_key(),
                ks.record().revocation_status,
                ks.record().revocation_context,
            )
        };

        let claims_res = self.verifier.verify_license_token_bound_at(
            &raw_token,
            &self.config.workspace_id,
            &self.config.product_id,
            &current_hwid,
            &device_vk,
            now_utc,
        );

        let (claims, rebind_needed) = match claims_res {
            Ok(c) => (c, false),
            Err((status, msg)) => {
                // Check if HWID drifted but signature, tenant, and device_key are intact (Case B)
                if let Ok(unbound) = self.verifier.verify_license_token_at(
                    &raw_token,
                    &self.config.workspace_id,
                    &self.config.product_id,
                    now_utc,
                ) {
                    if let Some(ref dk) = unbound.device_key {
                        if let Ok(token_vk) = TokenVerifier::parse_verifying_key_base64(dk) {
                            if token_vk == device_vk {
                                (unbound, true)
                            } else {
                                return (
                                    LeaseSnapshot {
                                        status,
                                        is_authorized: false,
                                        message: Some(msg),
                                        ..Default::default()
                                    },
                                    LocalHint::Clean,
                                    None,
                                );
                            }
                        } else {
                            return (
                                LeaseSnapshot {
                                    status,
                                    is_authorized: false,
                                    message: Some(msg),
                                    ..Default::default()
                                },
                                LocalHint::Clean,
                                None,
                            );
                        }
                    } else {
                        return (
                            LeaseSnapshot {
                                status,
                                is_authorized: false,
                                message: Some(msg),
                                ..Default::default()
                            },
                            LocalHint::Clean,
                            None,
                        );
                    }
                } else {
                    return (
                        LeaseSnapshot {
                            status,
                            is_authorized: false,
                            message: Some(msg),
                            ..Default::default()
                        },
                        LocalHint::Clean,
                        None,
                    );
                }
            }
        };

        // Check persisted revocation
        if rev_status != 0 {
            let persisted_code = match rev_status {
                5 => StatusCode::RequiresPortalDeactivation,
                6 => StatusCode::LicenseSuspendedOrRevoked,
                7 => StatusCode::VersionCeilingExceeded,
                8 => StatusCode::TamperOrSignatureInvalid,
                12 => StatusCode::KeyRevokedUpdateRequired,
                _ => StatusCode::RequiresPortalDeactivation,
            };

            let app_fp =
                Self::compute_app_fingerprint(&self.config.app_version, &self.supported_kids);
            let applies = if rev_context == [0u8; 8] {
                true
            } else {
                rev_context == app_fp
            };

            if applies {
                return (
                    LeaseSnapshot {
                        status: persisted_code,
                        is_authorized: false,
                        seat_id: Some(claims.seat_id.clone()),
                        masked_key: claims
                            .masked_key
                            .clone()
                            .or_else(|| Some(claims.sub.clone())),
                        buyer_email: claims.buyer_email.clone(),
                        last_verified_at_unix: Some(claims.iat),
                        offline_expires_at_unix: None,
                        is_within_offline_grace: false,
                        portal_url: None,
                        message: Some(format!("Persisted seat revocation: {:?}", persisted_code)),
                        entitlements: claims.entitlements.clone(),
                    },
                    LocalHint::RevocationPersisted(persisted_code),
                    Some(claims),
                );
            }
        }

        // If keystore has not yet been initialized with offline grace (0 duration)
        // and a valid, verified offline lease exists on disk, initialize the authoritative
        // keystore timeline from the signed token's iat and offline_grace_days.
        let ks_grace = {
            self.keystore
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .record()
                .grace_duration_seconds
        };
        if ks_grace == 0 {
            let grace_days = claims.offline_grace_days.unwrap_or(0);
            if grace_days > 0 {
                let grace_duration = grace_days.max(0) * 86400;
                let mut ks = self.keystore.lock().unwrap_or_else(|e| e.into_inner());
                ks.update_timeline(&self.storage, claims.iat, grace_duration);
                clock_status = ks.evaluate_clock_and_grace(now_utc);
            }
        }

        // Authoritative Keystore Timeline Check
        let (status, is_authorized) = if clock_status == StatusCode::TimeTamperDetected {
            (StatusCode::TimeTamperDetected, false)
        } else if clock_status == StatusCode::OfflineGraceExpired || now_utc > claims.exp {
            (StatusCode::OfflineGraceExpired, false)
        } else if rebind_needed {
            (StatusCode::TamperOrSignatureInvalid, false)
        } else {
            (StatusCode::Ok, true)
        };

        // Read stored heartbeat ACK for updated entitlements if valid
        let mut entitlements = claims.entitlements.clone();
        if let Some(raw_ack) = self.storage.read_ack() {
            if let Ok((_h, ack_claims)) = crate::jwt::decode_and_verify_jwt::<
                crate::types::HeartbeatAckClaims,
                _,
            >(&raw_ack, |h| self.verifier.resolve_key(h))
            {
                if ack_claims.aud == self.config.workspace_id
                    && ack_claims.product_id == self.config.product_id
                    && ack_claims.sub == claims.sub
                    && ack_claims.seat_id == claims.seat_id
                {
                    entitlements = ack_claims.entitlements;
                }
            }
        }

        let expires_at = {
            let ks = self.keystore.lock().unwrap_or_else(|e| e.into_inner());
            ks.record().last_validated_at_utc + ks.record().grace_duration_seconds
        };

        let snap = LeaseSnapshot {
            status,
            is_authorized,
            seat_id: Some(claims.seat_id.clone()),
            masked_key: claims
                .masked_key
                .clone()
                .or_else(|| Some(claims.sub.clone())),
            buyer_email: claims.buyer_email.clone(),
            last_verified_at_unix: Some(claims.iat),
            offline_expires_at_unix: Some(expires_at),
            is_within_offline_grace: is_authorized,
            portal_url: None,
            message: None,
            entitlements,
        };

        let hint = if rebind_needed {
            LocalHint::RebindRequired
        } else {
            LocalHint::Clean
        };

        (snap, hint, Some(claims))
    }

    pub fn initialize(&self) -> LeaseStatus {
        let now_utc = self.now_unix();
        let (snap, _hint, _claims) = self.evaluate_local(now_utc);

        if snap.is_authorized {
            self.keystore
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .advance_high_water_mark(&self.storage, now_utc);
        }

        self.cache.update(snap);

        if self.storage.read_lease().is_some() {
            self.start_heartbeat_worker();
        }

        self.cache.get_status()
    }

    #[inline(always)]
    pub fn is_authorized(&self) -> bool {
        self.cache.is_authorized()
    }

    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        self.is_authorized()
    }

    #[inline(always)]
    pub fn status(&self) -> StatusCode {
        self.cache.get_status().status
    }

    pub fn is_valid_blocking(&self, timeout: Duration) -> bool {
        self.status_blocking(timeout).status == StatusCode::Ok
    }

    pub fn status_blocking(&self, timeout: Duration) -> LeaseStatus {
        let now_utc = self.now_unix();
        let (snap, hint, claims) = self.evaluate_local(now_utc);

        if snap.status == StatusCode::NotActivated {
            self.cache.update(snap);
            return self.cache.get_status();
        }

        if snap.is_authorized && hint == LocalHint::Clean {
            self.keystore
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .advance_high_water_mark(&self.storage, now_utc);
            self.cache.update(snap);
            return self.cache.get_status();
        }

        // Needs sync or rebind
        if hint == LocalHint::RebindRequired {
            if let Some(c) = claims {
                return self.rebind(&c, timeout);
            }
        }

        self.heartbeat_with_timeout(timeout)
    }

    #[inline(always)]
    pub fn get_entitlement_bool(&self, key: &str, default_value: bool) -> bool {
        self.cache.get_entitlement_bool(key, default_value)
    }

    #[inline(always)]
    pub fn get_entitlement_i64(&self, key: &str, default_value: i64) -> i64 {
        self.cache.get_entitlement_i64(key, default_value)
    }

    #[inline(always)]
    pub fn get_entitlement_f64(&self, key: &str, default_value: f64) -> f64 {
        self.cache.get_entitlement_f64(key, default_value)
    }

    #[inline(always)]
    pub fn get_entitlement_string(&self, key: &str, default_value: &str) -> String {
        self.cache.get_entitlement_string(key, default_value)
    }

    pub fn get_status(&self) -> LeaseStatus {
        self.cache.get_status()
    }

    pub fn activate(&self, license_key: &str) -> ActivationResult {
        self.activate_with_timeout(license_key, Duration::from_secs(10))
    }

    pub fn activate_with_timeout(&self, license_key: &str, timeout: Duration) -> ActivationResult {
        let hwid = HWIDCollector::get_hwid();
        let hwid_components = HWIDCollector::get_components();
        let timestamp = self.now_unix();

        let mut nonce_bytes = [0u8; 16];
        rand::fill(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        let (pop_jwt, device_vk) = {
            let ks = self.keystore.lock().unwrap_or_else(|e| e.into_inner());
            let jwt_res = ks.sign_activation_pop_jwt(
                license_key,
                &hwid,
                hwid_components,
                &self.config.app_version,
                &self.config.api_base_url,
                &self.supported_kids,
                timestamp,
                &nonce,
            );
            (jwt_res, ks.verifying_key())
        };

        let pop_jwt = match pop_jwt {
            Ok(j) => j,
            Err(e) => {
                return ActivationResult {
                    success: false,
                    status: StatusCode::TamperOrSignatureInvalid,
                    message: format!("Failed to sign PoP JWT: {}", e),
                    seat_id: None,
                    portal_url: None,
                    buyer_email: None,
                    seats_active: None,
                    seat_limit: None,
                    lease_status: None,
                    token: None,
                };
            }
        };

        let body = serde_json::json!({
            "token": pop_jwt,
        });

        let url = format!("{}/v1/licenses/activate", self.config.api_base_url);
        let resp = ureq::post(&url)
            .config()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .build()
            .send_json(body);

        match resp {
            Ok(mut response) => {
                let status_code = response.status().as_u16();
                if response.status().is_success() {
                    let data: serde_json::Value = match response.body_mut().read_json() {
                        Ok(j) => j,
                        Err(e) => {
                            return ActivationResult {
                                success: false,
                                status: StatusCode::NetworkError,
                                message: format!("Failed to parse response: {}", e),
                                seat_id: None,
                                portal_url: None,
                                buyer_email: None,
                                seats_active: None,
                                seat_limit: None,
                                lease_status: None,
                                token: None,
                            }
                        }
                    };

                    let license_token = data["token"].as_str().unwrap_or_default();
                    if license_token.is_empty() {
                        return ActivationResult {
                            success: false,
                            status: StatusCode::TamperOrSignatureInvalid,
                            message: "Missing token in activation response".to_string(),
                            seat_id: None,
                            portal_url: None,
                            buyer_email: None,
                            seats_active: None,
                            seat_limit: None,
                            lease_status: None,
                            token: None,
                        };
                    }

                    let claims = match self.verifier.verify_license_token_bound_at(
                        license_token,
                        &self.config.workspace_id,
                        &self.config.product_id,
                        &hwid,
                        &device_vk,
                        timestamp,
                    ) {
                        Ok(c) => c,
                        Err((status, msg)) => {
                            return ActivationResult {
                                success: false,
                                status,
                                message: msg,
                                seat_id: None,
                                portal_url: None,
                                buyer_email: None,
                                seats_active: None,
                                seat_limit: None,
                                lease_status: None,
                                token: None,
                            };
                        }
                    };

                    let _ = self.storage.write_lease(license_token);

                    let grace_duration = claims.exp.saturating_sub(claims.iat).max(0);
                    self.keystore
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .update_timeline(&self.storage, claims.iat, grace_duration);

                    let expires_at = claims.iat + grace_duration;

                    let snap = LeaseSnapshot {
                        status: StatusCode::Ok,
                        is_authorized: true,
                        seat_id: Some(claims.seat_id.clone()),
                        masked_key: claims
                            .masked_key
                            .clone()
                            .or_else(|| Some(claims.sub.clone())),
                        buyer_email: claims.buyer_email.clone(),
                        last_verified_at_unix: Some(claims.iat),
                        offline_expires_at_unix: Some(expires_at),
                        is_within_offline_grace: true,
                        portal_url: None,
                        message: None,
                        entitlements: claims.entitlements.clone(),
                    };

                    self.cache.update(snap);
                    self.start_heartbeat_worker();

                    ActivationResult {
                        success: true,
                        status: StatusCode::Ok,
                        message: "Seat successfully activated".to_string(),
                        seat_id: Some(claims.seat_id),
                        portal_url: None,
                        buyer_email: claims.buyer_email,
                        seats_active: None,
                        seat_limit: None,
                        lease_status: Some(self.cache.get_status()),
                        token: Some(license_token.to_string()),
                    }
                } else {
                    let json: serde_json::Value =
                        response.body_mut().read_json().unwrap_or_default();
                    let code_str = json["code"].as_str().unwrap_or_default();
                    let msg = json["message"]
                        .as_str()
                        .unwrap_or("Activation rejected")
                        .to_string();
                    let portal_url = json["portal_url"].as_str().map(|s| s.to_string());
                    let buyer_email = json["buyer_email"].as_str().map(|s| s.to_string());

                    let status = if status_code == 403 {
                        if code_str == "VERSION_NOT_ENTITLED" {
                            StatusCode::VersionCeilingExceeded
                        } else if code_str == "KEY_REVOKED_UPDATE_REQUIRED" {
                            StatusCode::KeyRevokedUpdateRequired
                        } else {
                            StatusCode::SeatsExhausted
                        }
                    } else if status_code == 409 {
                        StatusCode::RequiresPortalDeactivation
                    } else {
                        StatusCode::TamperOrSignatureInvalid
                    };

                    ActivationResult {
                        success: false,
                        status,
                        message: msg,
                        seat_id: None,
                        portal_url,
                        buyer_email,
                        seats_active: json["seats_active"].as_i64().map(|v| v as i32),
                        seat_limit: json["seat_limit"].as_i64().map(|v| v as i32),
                        lease_status: Some(self.cache.get_status()),
                        token: None,
                    }
                }
            }
            Err(e) => ActivationResult {
                success: false,
                status: StatusCode::NetworkError,
                message: format!("Network error: {}", e),
                seat_id: None,
                portal_url: None,
                buyer_email: None,
                seats_active: None,
                seat_limit: None,
                lease_status: Some(self.cache.get_status()),
                token: None,
            },
        }
    }

    pub fn rebind(&self, claims: &LicenseJwtClaims, timeout: Duration) -> LeaseStatus {
        let res = self.activate_with_timeout(&claims.sub, timeout);
        if res.success {
            self.get_status()
        } else {
            let snap = LeaseSnapshot {
                status: res.status,
                is_authorized: false,
                seat_id: Some(claims.seat_id.clone()),
                masked_key: claims
                    .masked_key
                    .clone()
                    .or_else(|| Some(claims.sub.clone())),
                buyer_email: claims.buyer_email.clone(),
                last_verified_at_unix: Some(claims.iat),
                offline_expires_at_unix: None,
                is_within_offline_grace: false,
                portal_url: res.portal_url,
                message: Some(res.message),
                entitlements: claims.entitlements.clone(),
            };
            self.cache.update(snap);
            self.get_status()
        }
    }

    pub fn heartbeat_now(&self) -> LeaseStatus {
        self.heartbeat_with_timeout(Duration::from_secs(8))
    }

    pub fn heartbeat_with_timeout(&self, timeout: Duration) -> LeaseStatus {
        let now_utc = self.now_unix();
        Self::execute_heartbeat(
            &self.storage,
            &self.keystore,
            &self.verifier,
            &self.cache,
            &self.config.workspace_id,
            &self.config.product_id,
            &self.config.app_version,
            &self.config.api_base_url,
            &self.session_id,
            &self.supported_kids,
            now_utc,
            timeout,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_heartbeat(
        storage: &StorageManager,
        keystore: &Arc<Mutex<HardwareSealedKeystore>>,
        verifier: &TokenVerifier,
        cache: &Arc<StateAndEntitlementCache>,
        workspace_id: &str,
        product_id: &str,
        app_version: &str,
        api_base_url: &str,
        session_id: &str,
        supported_kids: &[String],
        now_utc: i64,
        timeout: Duration,
    ) -> LeaseStatus {
        let raw_token = match storage.read_lease() {
            Some(t) => t,
            None => {
                cache.clear();
                return cache.get_status();
            }
        };

        let current_hwid = HWIDCollector::get_hwid();
        let device_vk = keystore
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .verifying_key();

        let claims = match verifier.verify_license_token_bound_at(
            &raw_token,
            workspace_id,
            product_id,
            &current_hwid,
            &device_vk,
            now_utc,
        ) {
            Ok(c) => c,
            Err(_) => return cache.get_status(),
        };

        let mut nonce_bytes = [0u8; 16];
        rand::fill(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        let challenge_jwt = match keystore
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sign_heartbeat_challenge_jwt(
                &claims.sub,
                &claims.seat_id,
                &claims.hwid,
                session_id,
                app_version,
                api_base_url,
                supported_kids,
                now_utc,
                &nonce,
            ) {
            Ok(j) => j,
            Err(_) => return cache.get_status(),
        };

        let body = serde_json::json!({
            "token": challenge_jwt,
        });

        let url = format!("{}/v1/licenses/heartbeat", api_base_url);
        let resp = ureq::post(&url)
            .config()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .build()
            .send_json(body);

        match resp {
            Ok(mut response) => {
                let status_code = response.status().as_u16();
                if response.status().is_success() {
                    let data: serde_json::Value =
                        response.body_mut().read_json().unwrap_or_default();
                    let ack_token = data["token"].as_str().unwrap_or_default();

                    if let Ok(ack) = verifier.verify_heartbeat_ack_token(
                        ack_token,
                        &nonce,
                        workspace_id,
                        product_id,
                        &claims.sub,
                        &claims.seat_id,
                    ) {
                        if ack.status == "locked" {
                            let portal_url = data["portal_url"].as_str().map(|s| s.to_string());
                            keystore.lock().unwrap_or_else(|e| e.into_inner()).mutate(
                                storage,
                                |rec| {
                                    rec.revocation_status =
                                        StatusCode::RequiresPortalDeactivation as u32;
                                    rec.revocation_context = [0u8; 8];
                                },
                            );

                            let snap = LeaseSnapshot {
                            status: StatusCode::RequiresPortalDeactivation,
                            is_authorized: false,
                            seat_id: Some(claims.seat_id),
                            masked_key: claims.masked_key.or_else(|| Some(claims.sub.clone())),
                            buyer_email: claims.buyer_email,
                            last_verified_at_unix: Some(claims.iat),
                            offline_expires_at_unix: None,
                            is_within_offline_grace: false,
                            portal_url,
                            message: Some(
                                "Seat locked due to concurrent usage or policy. Portal deactivation required."
                                    .to_string(),
                            ),
                            entitlements: ack.entitlements,
                        };
                            cache.update(snap);
                            return cache.get_status();
                        } else if ack.status != "active" {
                            // High H1: Any non-active ack status is rejected
                            keystore.lock().unwrap_or_else(|e| e.into_inner()).mutate(
                                storage,
                                |rec| {
                                    rec.revocation_status =
                                        StatusCode::LicenseSuspendedOrRevoked as u32;
                                    rec.revocation_context = [0u8; 8];
                                },
                            );

                            let snap = LeaseSnapshot {
                                status: StatusCode::LicenseSuspendedOrRevoked,
                                is_authorized: false,
                                seat_id: Some(claims.seat_id),
                                masked_key: claims.masked_key.or_else(|| Some(claims.sub.clone())),
                                buyer_email: claims.buyer_email,
                                last_verified_at_unix: Some(claims.iat),
                                offline_expires_at_unix: None,
                                is_within_offline_grace: false,
                                portal_url: None,
                                message: Some(format!(
                                    "License status is '{}', not active",
                                    ack.status
                                )),
                                entitlements: ack.entitlements,
                            };
                            cache.update(snap);
                            return cache.get_status();
                        }

                        // Active heartbeat ACK: Persist ack token to disk for refreshed grace & entitlements
                        let _ = storage.write_ack(ack_token);

                        let grace_duration = ack.exp.saturating_sub(ack.iat).max(0);
                        keystore
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .update_timeline(storage, ack.iat, grace_duration);

                        let expires_at = ack.iat + grace_duration;

                        let snap = LeaseSnapshot {
                            status: StatusCode::Ok,
                            is_authorized: true,
                            seat_id: Some(claims.seat_id),
                            masked_key: claims.masked_key.or_else(|| Some(claims.sub.clone())),
                            buyer_email: claims.buyer_email,
                            last_verified_at_unix: Some(ack.iat),
                            offline_expires_at_unix: Some(expires_at),
                            is_within_offline_grace: true,
                            portal_url: None,
                            message: None,
                            entitlements: ack.entitlements,
                        };
                        cache.update(snap);
                    }
                } else if status_code == 401 {
                    // M6: Key rotated away or invalidated
                    keystore
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .mutate(storage, |rec| {
                            rec.revocation_status = StatusCode::TamperOrSignatureInvalid as u32;
                            rec.revocation_context = [0u8; 8];
                        });
                    let snap = LeaseSnapshot {
                        status: StatusCode::TamperOrSignatureInvalid,
                        is_authorized: false,
                        seat_id: Some(claims.seat_id),
                        masked_key: claims.masked_key.or_else(|| Some(claims.sub.clone())),
                        buyer_email: claims.buyer_email,
                        last_verified_at_unix: Some(claims.iat),
                        offline_expires_at_unix: None,
                        is_within_offline_grace: false,
                        portal_url: None,
                        message: Some("Heartbeat rejected: device key no longer bound".to_string()),
                        entitlements: claims.entitlements,
                    };
                    cache.update(snap);
                } else if status_code == 403 {
                    let json: serde_json::Value =
                        response.body_mut().read_json().unwrap_or_default();
                    let code_str = json["code"].as_str().unwrap_or_default();
                    let app_fp = Self::compute_app_fingerprint(app_version, supported_kids);

                    if code_str == "VERSION_NOT_ENTITLED" {
                        let portal_url = json["portal_url"].as_str().map(|s| s.to_string());
                        let msg = json["message"]
                            .as_str()
                            .unwrap_or("Version not entitled")
                            .to_string();

                        keystore
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .mutate(storage, |rec| {
                                rec.revocation_status = StatusCode::VersionCeilingExceeded as u32;
                                rec.revocation_context = app_fp;
                            });

                        let snap = LeaseSnapshot {
                            status: StatusCode::VersionCeilingExceeded,
                            is_authorized: false,
                            seat_id: Some(claims.seat_id),
                            masked_key: claims.masked_key.or_else(|| Some(claims.sub.clone())),
                            buyer_email: claims.buyer_email,
                            last_verified_at_unix: Some(claims.iat),
                            offline_expires_at_unix: None,
                            is_within_offline_grace: false,
                            portal_url,
                            message: Some(msg),
                            entitlements: claims.entitlements,
                        };
                        cache.update(snap);
                    } else if code_str == "KEY_REVOKED_UPDATE_REQUIRED" {
                        let portal_url = json["portal_url"].as_str().map(|s| s.to_string());
                        let msg = json["message"]
                            .as_str()
                            .unwrap_or("Workspace key revoked. Application update required.")
                            .to_string();

                        keystore
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .mutate(storage, |rec| {
                                rec.revocation_status = StatusCode::KeyRevokedUpdateRequired as u32;
                                rec.revocation_context = app_fp;
                            });

                        let snap = LeaseSnapshot {
                            status: StatusCode::KeyRevokedUpdateRequired,
                            is_authorized: false,
                            seat_id: Some(claims.seat_id),
                            masked_key: claims.masked_key.or_else(|| Some(claims.sub.clone())),
                            buyer_email: claims.buyer_email,
                            last_verified_at_unix: Some(claims.iat),
                            offline_expires_at_unix: None,
                            is_within_offline_grace: false,
                            portal_url,
                            message: Some(msg),
                            entitlements: claims.entitlements,
                        };
                        cache.update(snap);
                    } else {
                        keystore
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .mutate(storage, |rec| {
                                rec.revocation_status =
                                    StatusCode::LicenseSuspendedOrRevoked as u32;
                                rec.revocation_context = [0u8; 8];
                            });
                        let snap = LeaseSnapshot {
                            status: StatusCode::LicenseSuspendedOrRevoked,
                            is_authorized: false,
                            seat_id: Some(claims.seat_id),
                            masked_key: claims.masked_key.or_else(|| Some(claims.sub.clone())),
                            buyer_email: claims.buyer_email,
                            last_verified_at_unix: Some(claims.iat),
                            offline_expires_at_unix: None,
                            is_within_offline_grace: false,
                            portal_url: None,
                            message: Some("License forbidden or revoked".to_string()),
                            entitlements: claims.entitlements,
                        };
                        cache.update(snap);
                    }
                } else if status_code == 409 {
                    let json: serde_json::Value =
                        response.body_mut().read_json().unwrap_or_default();
                    let portal_url = json["portal_url"].as_str().map(|s| s.to_string());
                    keystore
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .mutate(storage, |rec| {
                            rec.revocation_status = StatusCode::RequiresPortalDeactivation as u32;
                            rec.revocation_context = [0u8; 8];
                        });

                    let snap = LeaseSnapshot {
                        status: StatusCode::RequiresPortalDeactivation,
                        is_authorized: false,
                        seat_id: Some(claims.seat_id),
                        masked_key: claims.masked_key.or_else(|| Some(claims.sub.clone())),
                        buyer_email: claims.buyer_email,
                        last_verified_at_unix: Some(claims.iat),
                        offline_expires_at_unix: None,
                        is_within_offline_grace: false,
                        portal_url,
                        message: Some("Seat requires customer portal deactivation.".to_string()),
                        entitlements: claims.entitlements,
                    };
                    cache.update(snap);
                }
            }
            _ => {
                // Network failure: do not revoke offline grace if locally valid
            }
        }

        cache.get_status()
    }

    pub fn deactivate(&self) -> Result<(), SeatlingError> {
        self.storage.delete_lease();
        self.cache.clear();
        self.stop_heartbeat_worker();
        Ok(())
    }

    pub fn shutdown(&self) {
        self.stop_heartbeat_worker();
    }

    fn start_heartbeat_worker(&self) {
        let mut handle_guard = self
            .worker_handle
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if handle_guard.is_some() {
            return;
        }

        {
            let mut stopped = self.worker_stop.0.lock().unwrap_or_else(|e| e.into_inner());
            *stopped = false;
        }
        let stop_pair = Arc::clone(&self.worker_stop);
        let interval_secs = u64::from(self.config.heartbeat_interval_seconds.max(1));
        let api_url = self.config.api_base_url.clone();
        let ws_id = self.config.workspace_id.clone();
        let prod_id = self.config.product_id.clone();
        let app_version = self.config.app_version.clone();
        let session_id = self.session_id.clone();
        let storage = StorageManager::new(
            &self.config.workspace_id,
            &self.config.product_id,
            self.config.storage_dir.as_deref(),
        );
        let keystore = Arc::clone(&self.keystore);
        let cache = Arc::clone(&self.cache);
        let custom_keys = self.config.public_keys.clone();
        let supported_kids = self.supported_kids.clone();
        let time_source = self.time_source.clone();

        let handle = thread::spawn(move || {
            let verifier = match TokenVerifier::new(&custom_keys) {
                Ok(v) => v,
                Err(_) => return,
            };

            let get_now = || -> i64 {
                if let Some(ref ts) = time_source {
                    ts()
                } else {
                    Self::current_unix_time()
                }
            };

            let tick_duration = Duration::from_secs(60);
            let mut last_hb = get_now();
            let mut last_hwm_disk = get_now();

            loop {
                {
                    let (lock, cvar) = &*stop_pair;
                    let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                    if *guard {
                        return;
                    }
                    let (guard, _) = cvar
                        .wait_timeout(guard, tick_duration)
                        .unwrap_or_else(|e| e.into_inner());
                    if *guard {
                        return;
                    }
                }

                let now = get_now();

                // Periodic offline grace tick & clock evaluation (Critical C3)
                let raw_token = storage.read_lease();
                if let Some(ref t) = raw_token {
                    let current_hwid = HWIDCollector::get_hwid();
                    let (clock_status, device_vk, rev_status) = {
                        let ks = keystore.lock().unwrap_or_else(|e| e.into_inner());
                        (
                            ks.evaluate_clock_and_grace(now),
                            ks.verifying_key(),
                            ks.record().revocation_status,
                        )
                    };

                    if rev_status == 0 {
                        let is_auth = clock_status == StatusCode::Ok;
                        if !is_auth {
                            let curr = cache.get_status();
                            let snap = LeaseSnapshot {
                                status: clock_status,
                                is_authorized: false,
                                seat_id: curr.seat_id,
                                masked_key: curr.masked_key,
                                buyer_email: curr.buyer_email,
                                last_verified_at_unix: curr.last_verified_at_unix,
                                offline_expires_at_unix: curr.offline_expires_at_unix,
                                is_within_offline_grace: false,
                                portal_url: curr.portal_url,
                                message: curr.message,
                                entitlements: curr.entitlements,
                            };
                            cache.update(snap);
                        } else if now > last_hwm_disk + 60 {
                            keystore
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .advance_high_water_mark(&storage, now);
                            last_hwm_disk = now;
                        }
                    }

                    // Check if heartbeat is due
                    if now.saturating_sub(last_hb) >= interval_secs as i64 {
                        last_hb = now;
                        // Execute rebind if HWID drifted, else execute heartbeat
                        let is_rebind = if let Ok(unbound) =
                            verifier.verify_license_token_at(t, &ws_id, &prod_id, now)
                        {
                            if !crate::verifier::constant_time_eq(
                                unbound.hwid.as_bytes(),
                                current_hwid.as_bytes(),
                            ) {
                                if let Some(ref dk) = unbound.device_key {
                                    if let Ok(token_vk) =
                                        TokenVerifier::parse_verifying_key_base64(dk)
                                    {
                                        token_vk == device_vk
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        };

                        if is_rebind {
                            let claims_opt = verifier
                                .verify_license_token_at(t, &ws_id, &prod_id, now)
                                .ok();
                            if let Some(claims) = claims_opt {
                                let mut nonce_bytes = [0u8; 16];
                                rand::fill(&mut nonce_bytes);
                                let nonce = hex::encode(nonce_bytes);

                                let pop_jwt_res = keystore
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .sign_activation_pop_jwt(
                                        &claims.sub,
                                        &current_hwid,
                                        HWIDCollector::get_components(),
                                        &app_version,
                                        &api_url,
                                        &supported_kids,
                                        now,
                                        &nonce,
                                    );

                                if let Ok(pop_jwt) = pop_jwt_res {
                                    let body = serde_json::json!({ "token": pop_jwt });
                                    let url = format!("{}/v1/licenses/activate", api_url);
                                    if let Ok(mut resp) = ureq::post(&url)
                                        .config()
                                        .timeout_global(Some(Duration::from_secs(10)))
                                        .build()
                                        .send_json(body)
                                    {
                                        if let Ok(data) =
                                            resp.body_mut().read_json::<serde_json::Value>()
                                        {
                                            if let Some(tok) = data["token"].as_str() {
                                                if let Ok(new_claims) = verifier
                                                    .verify_license_token_bound_at(
                                                        tok,
                                                        &ws_id,
                                                        &prod_id,
                                                        &current_hwid,
                                                        &device_vk,
                                                        now,
                                                    )
                                                {
                                                    let _ = storage.write_lease(tok);
                                                    let grace = new_claims
                                                        .exp
                                                        .saturating_sub(new_claims.iat)
                                                        .max(0);
                                                    keystore
                                                        .lock()
                                                        .unwrap_or_else(|e| e.into_inner())
                                                        .update_timeline(
                                                            &storage,
                                                            new_claims.iat,
                                                            grace,
                                                        );
                                                    let snap = LeaseSnapshot {
                                                        status: StatusCode::Ok,
                                                        is_authorized: true,
                                                        seat_id: Some(new_claims.seat_id),
                                                        masked_key: new_claims
                                                            .masked_key
                                                            .or(Some(new_claims.sub)),
                                                        buyer_email: new_claims.buyer_email,
                                                        last_verified_at_unix: Some(new_claims.iat),
                                                        offline_expires_at_unix: Some(
                                                            new_claims.iat + grace,
                                                        ),
                                                        is_within_offline_grace: true,
                                                        portal_url: None,
                                                        message: None,
                                                        entitlements: new_claims.entitlements,
                                                    };
                                                    cache.update(snap);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            Self::execute_heartbeat(
                                &storage,
                                &keystore,
                                &verifier,
                                &cache,
                                &ws_id,
                                &prod_id,
                                &app_version,
                                &api_url,
                                &session_id,
                                &supported_kids,
                                now,
                                Duration::from_secs(8),
                            );
                        }
                    }
                }
            }
        });

        *handle_guard = Some(handle);
    }

    fn stop_heartbeat_worker(&self) {
        {
            let (lock, cvar) = &*self.worker_stop;
            let mut stopped = lock.lock().unwrap_or_else(|e| e.into_inner());
            *stopped = true;
            cvar.notify_all();
        }
        let mut handle_guard = self
            .worker_handle
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(handle) = handle_guard.take() {
            let _ = handle.join();
        }
    }

    fn current_unix_time() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

impl Drop for SeatlingClient {
    fn drop(&mut self) {
        self.stop_heartbeat_worker();
    }
}
