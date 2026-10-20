use crate::types::{LeaseStatus, StatusCode};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct LeaseSnapshot {
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

impl Default for LeaseSnapshot {
    fn default() -> Self {
        Self {
            status: StatusCode::NotActivated,
            is_authorized: false,
            seat_id: None,
            masked_key: None,
            buyer_email: None,
            last_verified_at_unix: None,
            offline_expires_at_unix: None,
            is_within_offline_grace: false,
            portal_url: None,
            message: None,
            entitlements: HashMap::new(),
        }
    }
}

pub struct StateAndEntitlementCache {
    snapshot: ArcSwap<LeaseSnapshot>,
}

impl Default for StateAndEntitlementCache {
    fn default() -> Self {
        Self::new()
    }
}

impl StateAndEntitlementCache {
    pub fn new() -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(LeaseSnapshot::default()),
        }
    }

    #[inline(always)]
    pub fn is_authorized(&self) -> bool {
        self.snapshot.load().is_authorized
    }

    #[inline(always)]
    pub fn get_entitlement_bool(&self, key: &str, default_value: bool) -> bool {
        let guard = self.snapshot.load();
        guard
            .entitlements
            .get(key)
            .and_then(|v| v.as_bool())
            .unwrap_or(default_value)
    }

    #[inline(always)]
    pub fn get_entitlement_i64(&self, key: &str, default_value: i64) -> i64 {
        let guard = self.snapshot.load();
        guard
            .entitlements
            .get(key)
            .and_then(|v| v.as_i64())
            .unwrap_or(default_value)
    }

    #[inline(always)]
    pub fn get_entitlement_f64(&self, key: &str, default_value: f64) -> f64 {
        let guard = self.snapshot.load();
        guard
            .entitlements
            .get(key)
            .and_then(|v| v.as_f64())
            .unwrap_or(default_value)
    }

    #[inline(always)]
    pub fn get_entitlement_string(&self, key: &str, default_value: &str) -> String {
        let guard = self.snapshot.load();
        guard
            .entitlements
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| default_value.to_string())
    }

    pub fn get_status(&self) -> LeaseStatus {
        let s = self.snapshot.load();
        LeaseStatus {
            status: s.status,
            is_authorized: s.is_authorized,
            seat_id: s.seat_id.clone(),
            masked_key: s.masked_key.clone(),
            buyer_email: s.buyer_email.clone(),
            last_verified_at_unix: s.last_verified_at_unix,
            offline_expires_at_unix: s.offline_expires_at_unix,
            is_within_offline_grace: s.is_within_offline_grace,
            portal_url: s.portal_url.clone(),
            message: s.message.clone(),
            entitlements: s.entitlements.clone(),
        }
    }

    pub fn update(&self, snapshot: LeaseSnapshot) {
        self.snapshot.store(Arc::new(snapshot));
    }

    pub fn clear(&self) {
        self.snapshot.store(Arc::new(LeaseSnapshot::default()));
    }
}
