use napi_derive::napi;
use seatling::hwid::HWIDCollector;
use seatling::types::SeatlingConfig;
use seatling::SeatlingClient;
use std::collections::HashMap;

#[napi(object)]
pub struct JsSeatlingConfig {
    pub workspace_id: String,
    pub product_id: String,
    pub public_keys: HashMap<String, String>,
    pub app_version: Option<String>,
    pub api_base_url: Option<String>,
    pub heartbeat_interval_seconds: Option<u32>,
    pub storage_dir: Option<String>,
}

#[napi(object)]
pub struct JsLeaseStatus {
    pub status: String,
    pub is_authorized: bool,
    pub seat_id: Option<String>,
    pub masked_key: Option<String>,
    pub buyer_email: Option<String>,
    pub last_verified_at_unix: Option<i64>,
    pub offline_expires_at_unix: Option<i64>,
    pub is_within_offline_grace: bool,
    pub portal_url: Option<String>,
    pub message: Option<String>,
    pub entitlements_json: String,
}

#[napi(object)]
pub struct JsActivationResult {
    pub success: bool,
    pub status: String,
    pub message: String,
    pub seat_id: Option<String>,
    pub portal_url: Option<String>,
    pub buyer_email: Option<String>,
    pub seats_active: Option<i32>,
    pub seat_limit: Option<i32>,
    pub lease_status: Option<JsLeaseStatus>,
    pub token: Option<String>,
}

#[napi(object)]
pub struct JsHWIDComponents {
    pub cpu: String,
    pub mobo: String,
    pub disk: String,
    pub os_uuid: String,
}

fn to_js_lease_status(ls: seatling::types::LeaseStatus) -> JsLeaseStatus {
    let entitlements_json =
        serde_json::to_string(&ls.entitlements).unwrap_or_else(|_| "{}".to_string());
    JsLeaseStatus {
        status: ls.status.as_str().to_string(),
        is_authorized: ls.is_authorized,
        seat_id: ls.seat_id,
        masked_key: ls.masked_key,
        buyer_email: ls.buyer_email,
        last_verified_at_unix: ls.last_verified_at_unix,
        offline_expires_at_unix: ls.offline_expires_at_unix,
        is_within_offline_grace: ls.is_within_offline_grace,
        portal_url: ls.portal_url,
        message: ls.message,
        entitlements_json,
    }
}

#[napi]
pub struct SeatlingClientNative {
    inner: SeatlingClient,
}

#[napi]
impl SeatlingClientNative {
    #[napi(constructor)]
    pub fn new(config: JsSeatlingConfig) -> napi::Result<Self> {
        let rust_config = SeatlingConfig {
            workspace_id: config.workspace_id,
            product_id: config.product_id,
            public_keys: config.public_keys,
            app_version: config.app_version.unwrap_or_else(|| "1.0.0".to_string()),
            api_base_url: config
                .api_base_url
                .unwrap_or_else(|| "https://api.seatling.com".to_string()),
            heartbeat_interval_seconds: config.heartbeat_interval_seconds.unwrap_or(14400),
            storage_dir: config.storage_dir,
        };

        let inner = SeatlingClient::new(rust_config).map_err(napi::Error::from_reason)?;

        Ok(Self { inner })
    }

    #[napi]
    pub fn initialize(&self) -> JsLeaseStatus {
        to_js_lease_status(self.inner.initialize())
    }

    #[napi]
    pub fn is_authorized(&self) -> bool {
        self.inner.is_authorized()
    }

    #[napi]
    pub fn is_valid(&self) -> bool {
        self.inner.is_valid()
    }

    #[napi]
    pub fn status(&self) -> String {
        self.inner.status().as_str().to_string()
    }

    #[napi]
    pub fn is_valid_blocking(&self, timeout_ms: Option<u32>) -> bool {
        let timeout = std::time::Duration::from_millis(timeout_ms.unwrap_or(8000) as u64);
        self.inner.is_valid_blocking(timeout)
    }

    #[napi]
    pub fn status_blocking(&self, timeout_ms: Option<u32>) -> JsLeaseStatus {
        let timeout = std::time::Duration::from_millis(timeout_ms.unwrap_or(8000) as u64);
        to_js_lease_status(self.inner.status_blocking(timeout))
    }

    #[napi]
    pub fn get_session_id(&self) -> String {
        self.inner.session_id().to_string()
    }

    #[napi]
    pub fn get_status(&self) -> JsLeaseStatus {
        to_js_lease_status(self.inner.get_status())
    }

    #[napi]
    pub fn get_entitlement_bool(&self, key: String, default_value: bool) -> bool {
        self.inner.get_entitlement_bool(&key, default_value)
    }

    #[napi]
    pub fn get_entitlement_number(&self, key: String, default_value: f64) -> f64 {
        self.inner.get_entitlement_f64(&key, default_value)
    }

    #[napi]
    pub fn get_entitlement_string(&self, key: String, default_value: Option<String>) -> String {
        let def = default_value.unwrap_or_default();
        self.inner.get_entitlement_string(&key, &def)
    }

    #[napi]
    pub fn activate(&self, license_key: String) -> JsActivationResult {
        let res = self.inner.activate(&license_key);
        JsActivationResult {
            success: res.success,
            status: res.status.as_str().to_string(),
            message: res.message,
            seat_id: res.seat_id,
            portal_url: res.portal_url,
            buyer_email: res.buyer_email,
            seats_active: res.seats_active,
            seat_limit: res.seat_limit,
            lease_status: res.lease_status.map(to_js_lease_status),
            token: res.token,
        }
    }

    #[napi]
    pub fn heartbeat_now(&self) -> JsLeaseStatus {
        to_js_lease_status(self.inner.heartbeat_now())
    }

    #[napi]
    pub fn heartbeat_with_timeout(&self, timeout_ms: Option<u32>) -> JsLeaseStatus {
        let timeout = std::time::Duration::from_millis(timeout_ms.unwrap_or(8000) as u64);
        to_js_lease_status(self.inner.heartbeat_with_timeout(timeout))
    }

    #[napi]
    pub fn deactivate(&self) -> bool {
        self.inner.deactivate().is_ok()
    }

    #[napi]
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

#[napi]
pub struct StorageManagerNative {
    inner: seatling::storage::StorageManager,
}

#[napi]
impl StorageManagerNative {
    #[napi(constructor)]
    pub fn new(workspace_id: String, product_id: String, storage_dir: Option<String>) -> Self {
        let inner = seatling::storage::StorageManager::new(
            &workspace_id,
            &product_id,
            storage_dir.as_deref(),
        );
        Self { inner }
    }

    #[napi]
    pub fn get_storage_dir(&self) -> String {
        self.inner.get_dir().display().to_string()
    }

    #[napi]
    pub fn get_lease_path(&self) -> String {
        self.inner.lease_path().display().to_string()
    }

    #[napi]
    pub fn get_keystore_path(&self) -> String {
        self.inner.keystore_path().display().to_string()
    }

    #[napi]
    pub fn read_lease(&self) -> Option<String> {
        self.inner.read_lease()
    }

    #[napi]
    pub fn write_lease(&self, content: String) -> bool {
        self.inner.write_lease(&content).is_ok()
    }

    #[napi]
    pub fn read_keystore(&self) -> Option<String> {
        self.inner.read_keystore()
    }

    #[napi]
    pub fn write_keystore(&self, content: String) -> bool {
        self.inner.write_keystore(&content).is_ok()
    }

    #[napi]
    pub fn delete_lease(&self) {
        self.inner.delete_lease();
    }
}

#[napi]
pub struct HardwareSealedKeystoreNative {
    inner: seatling::keystore::HardwareSealedKeystore,
}

#[napi]
impl HardwareSealedKeystoreNative {
    #[napi(constructor)]
    pub fn new(
        workspace_id: Option<String>,
        product_id: Option<String>,
        storage_dir: Option<String>,
    ) -> Self {
        let ws = workspace_id.unwrap_or_else(|| "default".to_string());
        let prod = product_id.unwrap_or_else(|| "default".to_string());
        let storage = seatling::storage::StorageManager::new(&ws, &prod, storage_dir.as_deref());
        let inner = seatling::keystore::HardwareSealedKeystore::load_or_generate(&storage);
        Self { inner }
    }

    #[napi]
    pub fn get_public_key_base64(&self) -> String {
        self.inner.public_key_base64()
    }

    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_activation_pop_jwt(
        &self,
        key: String,
        hwid: String,
        hwid_components: JsHWIDComponents,
        app_version: String,
        aud: String,
        timestamp: i64,
        nonce: String,
        supported_kids: Option<Vec<String>>,
    ) -> napi::Result<String> {
        let comps = seatling::types::HWIDComponents {
            cpu: hwid_components.cpu,
            mobo: hwid_components.mobo,
            disk: hwid_components.disk,
            os_uuid: hwid_components.os_uuid,
        };
        let kids = supported_kids.unwrap_or_default();
        self.inner
            .sign_activation_pop_jwt(
                &key,
                &hwid,
                comps,
                &app_version,
                &aud,
                &kids,
                timestamp,
                &nonce,
            )
            .map_err(napi::Error::from_reason)
    }

    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_heartbeat_challenge_jwt(
        &self,
        key: String,
        seat_id: String,
        hwid: String,
        session_id: String,
        app_version: String,
        aud: String,
        timestamp: i64,
        nonce: String,
        supported_kids: Option<Vec<String>>,
    ) -> napi::Result<String> {
        let kids = supported_kids.unwrap_or_default();
        self.inner
            .sign_heartbeat_challenge_jwt(
                &key,
                &seat_id,
                &hwid,
                &session_id,
                &app_version,
                &aud,
                &kids,
                timestamp,
                &nonce,
            )
            .map_err(napi::Error::from_reason)
    }

    #[napi]
    pub fn sign_activation_proof(
        &self,
        key: String,
        hwid: String,
        timestamp: i64,
        supported_kids: Option<Vec<String>>,
    ) -> String {
        let comps = HWIDCollector::get_components();
        let kids = supported_kids.unwrap_or_default();
        self.inner.sign_activation_proof(
            &key,
            &hwid,
            comps,
            "1.0.0",
            "https://api.seatling.com",
            &kids,
            timestamp,
            "nonce",
        )
    }

    #[napi]
    pub fn sign_heartbeat(
        &self,
        key: String,
        hwid: String,
        session_id: String,
        nonce: String,
        timestamp: i64,
        supported_kids: Option<Vec<String>>,
    ) -> String {
        let kids = supported_kids.unwrap_or_default();
        self.inner.sign_heartbeat(
            &key,
            "seat_01",
            &hwid,
            &session_id,
            "1.0.0",
            "https://api.seatling.com",
            &kids,
            &nonce,
            timestamp,
        )
    }

    #[napi]
    pub fn sign_deactivation(
        &self,
        key: String,
        seat_id: String,
        hwid: String,
        nonce: String,
        timestamp: i64,
    ) -> String {
        self.inner
            .sign_deactivation(&key, &seat_id, &hwid, &nonce, timestamp)
    }
}

#[napi]
pub struct TokenVerifierNative {
    inner: seatling::verifier::TokenVerifier,
}

#[napi]
impl TokenVerifierNative {
    #[napi(constructor)]
    pub fn new(public_keys: HashMap<String, String>) -> napi::Result<Self> {
        let inner = seatling::verifier::TokenVerifier::new(&public_keys)
            .map_err(napi::Error::from_reason)?;
        Ok(Self { inner })
    }

    #[napi]
    pub fn verify_license_token(
        &self,
        token: String,
        expected_workspace_id: String,
        expected_product_id: String,
    ) -> napi::Result<String> {
        let claims = self
            .inner
            .verify_license_token(&token, &expected_workspace_id, &expected_product_id)
            .map_err(|(status, msg)| {
                napi::Error::from_reason(format!("{}: {}", status.as_str(), msg))
            })?;
        serde_json::to_string(&claims).map_err(|e| napi::Error::from_reason(e.to_string()))
    }
}

#[napi]
pub struct StateAndEntitlementCacheNative {
    inner: seatling::cache::StateAndEntitlementCache,
}

impl Default for StateAndEntitlementCacheNative {
    fn default() -> Self {
        Self::new()
    }
}

#[napi]
impl StateAndEntitlementCacheNative {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: seatling::cache::StateAndEntitlementCache::new(),
        }
    }

    #[napi]
    pub fn is_authorized(&self) -> bool {
        self.inner.is_authorized()
    }

    #[napi]
    pub fn get_status(&self) -> JsLeaseStatus {
        to_js_lease_status(self.inner.get_status())
    }

    #[napi]
    pub fn get_entitlement_bool(&self, key: String, default_value: bool) -> bool {
        self.inner.get_entitlement_bool(&key, default_value)
    }

    #[napi]
    pub fn get_entitlement_number(&self, key: String, default_value: f64) -> f64 {
        self.inner.get_entitlement_f64(&key, default_value)
    }

    #[napi]
    pub fn get_entitlement_string(&self, key: String, default_value: Option<String>) -> String {
        let def = default_value.unwrap_or_default();
        self.inner.get_entitlement_string(&key, &def)
    }

    #[napi]
    pub fn clear(&self) {
        self.inner.clear();
    }
}

#[napi]
pub fn get_hwid() -> String {
    HWIDCollector::get_hwid()
}

#[napi]
pub fn get_hwid_components() -> JsHWIDComponents {
    let c = HWIDCollector::get_components();
    JsHWIDComponents {
        cpu: c.cpu,
        mobo: c.mobo,
        disk: c.disk,
        os_uuid: c.os_uuid,
    }
}

#[napi]
pub fn fuzzy_match_quorum(base: JsHWIDComponents, current: JsHWIDComponents) -> bool {
    let b = seatling::types::HWIDComponents {
        cpu: base.cpu,
        mobo: base.mobo,
        disk: base.disk,
        os_uuid: base.os_uuid,
    };
    let c = seatling::types::HWIDComponents {
        cpu: current.cpu,
        mobo: current.mobo,
        disk: current.disk,
        os_uuid: current.os_uuid,
    };
    HWIDCollector::fuzzy_match_quorum(&b, &c)
}

#[napi]
pub fn weighted_score(base: JsHWIDComponents, current: JsHWIDComponents) -> u32 {
    let b = seatling::types::HWIDComponents {
        cpu: base.cpu,
        mobo: base.mobo,
        disk: base.disk,
        os_uuid: base.os_uuid,
    };
    let c = seatling::types::HWIDComponents {
        cpu: current.cpu,
        mobo: current.mobo,
        disk: current.disk,
        os_uuid: current.os_uuid,
    };
    HWIDCollector::weighted_score(&b, &c)
}
