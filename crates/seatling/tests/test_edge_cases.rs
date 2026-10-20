use base64::Engine;
use seatling::jwt::{encode_eddsa_jwt, JwtHeader};
use seatling::types::{LicenseJwtClaims, SeatlingConfig, StatusCode};
use seatling::verifier::TokenVerifier;
use seatling::SeatlingClient;
use std::time::Duration;

#[test]
fn test_token_verifier_cryptographic_edge_cases() {
    let dummy_sk = ed25519_dalek::SigningKey::from_bytes(&[55u8; 32]);
    let dummy_vk = dummy_sk.verifying_key();
    let dummy_vk_b64 = base64::engine::general_purpose::STANDARD.encode(dummy_vk.as_bytes());

    let mut keys_map = std::collections::HashMap::new();
    keys_map.insert("test_kid_edge".to_string(), dummy_vk_b64);
    let verifier = TokenVerifier::new(&keys_map).expect("verifier creation");

    let now = 1_700_000_000i64;

    let base_claims = LicenseJwtClaims {
        iss: "seatling".to_string(),
        sub: "SEAT-EDGE-01".to_string(),
        aud: "ws_edge".to_string(),
        product_id: "prod_edge".to_string(),
        seat_id: "seat_01".to_string(),
        masked_key: None,
        buyer_email: None,
        hwid: "test_hwid".to_string(),
        device_key: None,
        app_version: "1.0.0".to_string(),
        iat: now,
        nbf: Some(now),
        exp: now + 86400,
        offline_grace_days: Some(1),
        status: "active".to_string(),
        entitlements: std::collections::HashMap::new(),
    };

    // 1. Inverted validity window: exp < iat
    let mut inverted_claims = base_claims.clone();
    inverted_claims.exp = now - 100;
    let header = JwtHeader::new("seatling-license+jwt", Some("test_kid_edge"));
    let inverted_token = encode_eddsa_jwt(&header, &inverted_claims, &dummy_sk).unwrap();
    let res_inv = verifier.verify_license_token_at(&inverted_token, "ws_edge", "prod_edge", now);
    assert_eq!(res_inv.unwrap_err().0, StatusCode::TamperOrSignatureInvalid);

    // 2. Clock skew tolerance: iat at now + 290s (passes <= 300s)
    let mut skew_claims = base_claims.clone();
    skew_claims.iat = now + 290;
    skew_claims.nbf = Some(now + 290);
    skew_claims.exp = now + 86400;
    let skew_token = encode_eddsa_jwt(&header, &skew_claims, &dummy_sk).unwrap();
    let res_skew = verifier.verify_license_token_at(&skew_token, "ws_edge", "prod_edge", now);
    assert!(res_skew.is_ok(), "iat within 300s skew tolerance must pass");

    // 3. Clock skew exceeded: iat at now + 305s (fails > 300s)
    let mut future_claims = base_claims.clone();
    future_claims.iat = now + 305;
    future_claims.nbf = Some(now + 305);
    future_claims.exp = now + 86400;
    let future_token = encode_eddsa_jwt(&header, &future_claims, &dummy_sk).unwrap();
    let res_future = verifier.verify_license_token_at(&future_token, "ws_edge", "prod_edge", now);
    assert_eq!(
        res_future.unwrap_err().0,
        StatusCode::TamperOrSignatureInvalid,
        "iat exceeding 300s skew must be rejected"
    );

    // 4. Algorithm substitution: typ seatling-license+jwt with unsupported alg "none"
    let raw_header =
        "{\"alg\":\"none\",\"typ\":\"seatling-license+jwt\",\"kid\":\"test_kid_edge\"}";
    let h_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_header);
    let c_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&base_claims).unwrap());
    let fake_token = format!("{}.{}.fake_signature", h_b64, c_b64);
    let res_alg = verifier.verify_license_token_at(&fake_token, "ws_edge", "prod_edge", now);
    assert_eq!(res_alg.unwrap_err().0, StatusCode::TamperOrSignatureInvalid);

    // 5. Malformed JWT parts
    let res_malformed =
        verifier.verify_license_token_at("only_one_part", "ws_edge", "prod_edge", now);
    assert_eq!(
        res_malformed.unwrap_err().0,
        StatusCode::TamperOrSignatureInvalid
    );

    // 6. Missing mandatory device_key claim in bound verification
    let bound_token = encode_eddsa_jwt(&header, &base_claims, &dummy_sk).unwrap();
    let res_missing_dev = verifier.verify_license_token_bound_at(
        &bound_token,
        "ws_edge",
        "prod_edge",
        "test_hwid",
        &dummy_vk,
        now,
    );
    assert_eq!(
        res_missing_dev.unwrap_err().0,
        StatusCode::TamperOrSignatureInvalid
    );
}

#[test]
fn test_corrupted_storage_and_empty_file_recovery() {
    let tmp_dir = format!(
        "{}/seatling_corrupt_test_{}",
        std::env::temp_dir().display(),
        std::process::id()
    );

    let storage = seatling::StorageManager::new("ws_corrupt", "prod_corrupt", Some(&tmp_dir));

    // 1. Write 0-byte file to lease.seatling
    storage.write_lease("").unwrap();
    assert_eq!(storage.read_lease(), Some("".to_string()));

    let dummy_vk_b64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".to_string();
    let mut public_keys = std::collections::HashMap::new();
    public_keys.insert("kid_1".to_string(), dummy_vk_b64);

    let cfg = SeatlingConfig {
        workspace_id: "ws_corrupt".to_string(),
        product_id: "prod_corrupt".to_string(),
        public_keys,
        app_version: "1.0.0".to_string(),
        api_base_url: "https://api.seatling.com".to_string(),
        heartbeat_interval_seconds: 14400,
        storage_dir: Some(tmp_dir.clone()),
    };

    let client = SeatlingClient::new(cfg).unwrap();
    // Empty lease should cleanly evaluate to TamperOrSignatureInvalid without crashing
    let init_status = client.initialize();
    assert_eq!(init_status.status, StatusCode::TamperOrSignatureInvalid);
    assert!(!client.is_authorized());

    // 2. Corrupt keystore.bin JSON with invalid bytes
    storage
        .write_keystore("{\"version\": 2, \"corrupt_json\": ")
        .unwrap();
    let recovered_keystore = seatling::HardwareSealedKeystore::load_or_generate(&storage);
    // Unsealing fails, so fresh keypair generated and persisted
    assert!(!recovered_keystore.public_key_base64().is_empty());
    assert!(
        storage.read_keystore().unwrap().contains("\"version\":2")
            || storage.read_keystore().unwrap().contains("\"version\": 2")
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_v4_scoped_revocation_context() {
    let tmp_dir = format!(
        "{}/seatling_scoped_rev_test_{}",
        std::env::temp_dir().display(),
        std::process::id()
    );

    let storage = seatling::StorageManager::new("ws_rev", "prod_rev", Some(&tmp_dir));
    let mut keystore = seatling::HardwareSealedKeystore::load_or_generate(&storage);

    // Compute app fingerprint for v1.0.0
    let app_v1_fp = SeatlingClient::compute_app_fingerprint("1.0.0", &["kid_1".to_string()]);
    assert_ne!(app_v1_fp, [0u8; 8]);

    // Mutate keystore to set persisted revocation for VersionCeilingExceeded scoped to app_v1_fp
    keystore.mutate(&storage, |rec| {
        rec.revocation_status = StatusCode::VersionCeilingExceeded as u32;
        rec.revocation_context = app_v1_fp;
    });

    // Create client running app version 1.0.0 -> should trigger persisted revocation
    let mut public_keys = std::collections::HashMap::new();
    let vk_b64 = keystore.public_key_base64();
    public_keys.insert("kid_1".to_string(), vk_b64.clone());

    // Write a valid dummy lease
    let dummy_sk = ed25519_dalek::SigningKey::from_bytes(&[88u8; 32]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = LicenseJwtClaims {
        iss: "seatling".to_string(),
        sub: "SEAT-REV-01".to_string(),
        aud: "ws_rev".to_string(),
        product_id: "prod_rev".to_string(),
        seat_id: "seat_01".to_string(),
        masked_key: None,
        buyer_email: None,
        hwid: seatling::HWIDCollector::get_hwid(),
        device_key: Some(vk_b64),
        app_version: "1.0.0".to_string(),
        iat: now,
        nbf: Some(now),
        exp: now + 86400,
        offline_grace_days: Some(1),
        status: "active".to_string(),
        entitlements: std::collections::HashMap::new(),
    };
    let token = encode_eddsa_jwt(
        &JwtHeader::new("seatling-license+jwt", Some("kid_1")),
        &claims,
        &dummy_sk,
    )
    .unwrap();
    storage.write_lease(&token).unwrap();

    let cfg_v1 = SeatlingConfig {
        workspace_id: "ws_rev".to_string(),
        product_id: "prod_rev".to_string(),
        public_keys: {
            let mut m = std::collections::HashMap::new();
            let vk = dummy_sk.verifying_key();
            m.insert(
                "kid_1".to_string(),
                base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
            );
            m
        },
        app_version: "1.0.0".to_string(),
        api_base_url: "https://api.seatling.com".to_string(),
        heartbeat_interval_seconds: 14400,
        storage_dir: Some(tmp_dir.clone()),
    };

    let client_v1 = SeatlingClient::new(cfg_v1).unwrap();
    let status_v1 = client_v1.initialize();
    assert_eq!(status_v1.status, StatusCode::VersionCeilingExceeded);
    assert!(!client_v1.is_authorized());

    // Client running upgraded app version 2.0.0 -> fingerprint does not match context, revocation ignored!
    let cfg_v2 = SeatlingConfig {
        workspace_id: "ws_rev".to_string(),
        product_id: "prod_rev".to_string(),
        public_keys: {
            let mut m = std::collections::HashMap::new();
            let vk = dummy_sk.verifying_key();
            m.insert(
                "kid_1".to_string(),
                base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
            );
            m
        },
        app_version: "2.0.0".to_string(), // Upgraded version
        api_base_url: "https://api.seatling.com".to_string(),
        heartbeat_interval_seconds: 14400,
        storage_dir: Some(tmp_dir.clone()),
    };

    let client_v2 = SeatlingClient::new(cfg_v2).unwrap();
    let status_v2 = client_v2.initialize();
    assert_eq!(status_v2.status, StatusCode::Ok);
    assert!(client_v2.is_authorized());

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_file_lock_timeout_and_release() {
    let tmp_dir = format!(
        "{}/seatling_lock_test_{}",
        std::env::temp_dir().display(),
        std::process::id()
    );

    let storage = seatling::StorageManager::new("ws_lock", "prod_lock", Some(&tmp_dir));

    // Acquire lock on thread 1
    let lock1 = storage.acquire_lock(Duration::from_millis(500));
    assert!(lock1.is_ok());

    // Attempting to acquire lock on thread 2 should time out
    let storage_clone = seatling::StorageManager::new("ws_lock", "prod_lock", Some(&tmp_dir));
    let handle = std::thread::spawn(move || storage_clone.acquire_lock(Duration::from_millis(100)));

    let res = handle.join().unwrap();
    assert!(res.is_err(), "Contended lock acquisition must time out");

    // Dropping lock1 releases it
    drop(lock1);

    // Now acquiring lock succeeds
    let lock2 = storage.acquire_lock(Duration::from_millis(500));
    assert!(lock2.is_ok());

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
