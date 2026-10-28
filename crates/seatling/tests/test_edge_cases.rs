use base64::Engine;
use seatling::jwt::{encode_eddsa_jwt, JwtHeader};
use seatling::types::{HeartbeatAckClaims, LicenseJwtClaims, SeatlingConfig, StatusCode};
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

#[test]
fn test_security_hardening_regressions() {
    let tmp_dir = format!(
        "{}/seatling_sec_reg_test_{}",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let storage = seatling::StorageManager::new("ws_sec", "prod_sec", Some(&tmp_dir));
    let mut keystore = seatling::HardwareSealedKeystore::load_or_generate(&storage);
    let initial_vk_b64 = keystore.public_key_base64();

    // 1. Snapshot rollback of keystore.bin after state mutation must fail unsealing
    let snapshot_keystore_json = storage.read_keystore().expect("read initial keystore");
    keystore.mutate(&storage, |rec| {
        rec.revocation_status = StatusCode::LicenseSuspendedOrRevoked as u32;
    });
    // Attacker restores old keystore.bin without matching rotated .keystore.secret
    storage.write_keystore(&snapshot_keystore_json).unwrap();
    let after_rollback = seatling::HardwareSealedKeystore::load_or_generate(&storage);
    assert_ne!(
        after_rollback.public_key_base64(),
        initial_vk_b64,
        "Rolled-back keystore.bin must not unseal original keypair"
    );

    // 2. Post-deactivate lease replay must be rejected due to device key rotation
    let dummy_sk = ed25519_dalek::SigningKey::from_bytes(&[91u8; 32]);
    let dummy_vk = dummy_sk.verifying_key();
    let dummy_vk_b64 = base64::engine::general_purpose::STANDARD.encode(dummy_vk.as_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let current_dev_vk = after_rollback.public_key_base64();
    let claims = LicenseJwtClaims {
        iss: "seatling".to_string(),
        sub: "SEAT-REPLAY-01".to_string(),
        aud: "ws_sec".to_string(),
        product_id: "prod_sec".to_string(),
        seat_id: "seat_01".to_string(),
        masked_key: None,
        buyer_email: None,
        hwid: seatling::HWIDCollector::get_hwid(),
        device_key: Some(current_dev_vk),
        app_version: "1.0.0".to_string(),
        iat: now,
        nbf: Some(now),
        exp: now + 86400,
        offline_grace_days: Some(1),
        status: "active".to_string(),
        entitlements: std::collections::HashMap::new(),
    };
    let lease_jwt = encode_eddsa_jwt(
        &JwtHeader::new("seatling-license+jwt", Some("kid_sec")),
        &claims,
        &dummy_sk,
    )
    .unwrap();
    storage.write_lease(&lease_jwt).unwrap();

    let mut public_keys = std::collections::HashMap::new();
    public_keys.insert("kid_sec".to_string(), dummy_vk_b64);

    let cfg = SeatlingConfig {
        workspace_id: "ws_sec".to_string(),
        product_id: "prod_sec".to_string(),
        public_keys: public_keys.clone(),
        app_version: "1.0.0".to_string(),
        api_base_url: "https://api.seatling.com".to_string(),
        heartbeat_interval_seconds: 14400,
        storage_dir: Some(tmp_dir.clone()),
    };

    let client = SeatlingClient::new(cfg.clone()).unwrap();
    assert_eq!(client.initialize().status, StatusCode::Ok);
    assert!(client.is_authorized());

    // Deactivate rotates device keypair; restoring backed-up lease_jwt must fail
    client.deactivate().unwrap();
    storage.write_lease(&lease_jwt).unwrap();
    assert_eq!(
        client.initialize().status,
        StatusCode::TamperOrSignatureInvalid
    );
    assert!(!client.is_authorized());

    // 3. Insecure or malformed api_base_url must be rejected
    for bad_url in [
        "http://api.seatling.com",
        "https://api.seatling.com?x=1",
        "https://api.seatling.com#frag",
        "https://user@api.seatling.com",
    ] {
        let mut bad_cfg = cfg.clone();
        bad_cfg.api_base_url = bad_url.to_string();
        assert!(
            SeatlingClient::new(bad_cfg).is_err(),
            "Expected error for bad api_base_url: {}",
            bad_url
        );
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_security_audit_remediations_v7() {
    use base64::Engine;
    use seatling::jwt::decode_and_verify_jwt;

    let mut csprng = rand::rng();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let now = 1774000000i64;

    // 1. JWT length limit (> 32KB)
    let huge_token = "a".repeat(33 * 1024);
    assert!(
        decode_and_verify_jwt::<serde_json::Value, _>(&huge_token, |_| Ok(verifying_key)).is_err()
    );

    // 2. Pre-auth JWT deserialization rejection with invalid signature
    let header = JwtHeader::new("seatling-license+jwt", Some("kid_audit"));
    let claims = LicenseJwtClaims {
        iss: "https://api.seatling.com".to_string(),
        sub: "key_audit".to_string(),
        aud: "ws_audit".to_string(),
        product_id: "prod_audit".to_string(),
        seat_id: "seat_audit".to_string(),
        masked_key: None,
        buyer_email: None,
        hwid: "hwid_audit".to_string(),
        device_key: None,
        app_version: "1.0.0".to_string(),
        iat: now,
        nbf: None,
        exp: now + 3600,
        offline_grace_days: None,
        status: "active".to_string(),
        entitlements: std::collections::HashMap::new(),
    };
    let valid_jwt = encode_eddsa_jwt(&header, &claims, &signing_key).unwrap();
    let parts: Vec<&str> = valid_jwt.split('.').collect();
    let tampered_sig_jwt = format!("{}.{}.{}", parts[0], parts[1], "A".repeat(86));
    assert!(
        decode_and_verify_jwt::<LicenseJwtClaims, _>(&tampered_sig_jwt, |_| Ok(verifying_key))
            .is_err()
    );

    // 3. Heartbeat ACK validation: verify_heartbeat_ack_token_at rejects future iat and expired exp
    let mut public_keys = std::collections::HashMap::new();
    let vk_b64 = base64::engine::general_purpose::STANDARD.encode(verifying_key.to_bytes());
    public_keys.insert("kid_audit".to_string(), vk_b64.clone());
    let verifier = TokenVerifier::new(&public_keys).unwrap();

    let ack_header = JwtHeader::new("seatling-heartbeat-ack+jwt", Some("kid_audit"));
    let mut ack_claims = HeartbeatAckClaims {
        jti: "nonce_audit".to_string(),
        iss: "https://api.seatling.com".to_string(),
        aud: "ws_audit".to_string(),
        sub: "sub_audit".to_string(),
        seat_id: "seat_audit".to_string(),
        product_id: "prod_audit".to_string(),
        status: "active".to_string(),
        iat: now + 400, // exceeds 300s skew tolerance
        exp: now + 3600,
        entitlements: std::collections::HashMap::new(),
    };
    let future_ack_jwt = encode_eddsa_jwt(&ack_header, &ack_claims, &signing_key).unwrap();
    let res_future = verifier.verify_heartbeat_ack_token_at(
        &future_ack_jwt,
        "nonce_audit",
        "ws_audit",
        "prod_audit",
        "sub_audit",
        "seat_audit",
        now,
    );
    assert_eq!(
        res_future.unwrap_err().0,
        StatusCode::TamperOrSignatureInvalid
    );

    // Expired ACK
    ack_claims.iat = now - 3600;
    ack_claims.exp = now - 100;
    let expired_ack_jwt = encode_eddsa_jwt(&ack_header, &ack_claims, &signing_key).unwrap();
    let res_expired = verifier.verify_heartbeat_ack_token_at(
        &expired_ack_jwt,
        "nonce_audit",
        "ws_audit",
        "prod_audit",
        "sub_audit",
        "seat_audit",
        now,
    );
    assert_eq!(
        res_expired.unwrap_err().0,
        StatusCode::TamperOrSignatureInvalid
    );

    // 4. Identifier and key count validation in SeatlingClient::new
    let base_cfg = SeatlingConfig {
        workspace_id: "ws_valid".to_string(),
        product_id: "prod_valid".to_string(),
        public_keys: public_keys.clone(),
        app_version: "1.0.0".to_string(),
        api_base_url: "https://api.seatling.com".to_string(),
        heartbeat_interval_seconds: 14400,
        storage_dir: None,
    };

    let mut bad_ws = base_cfg.clone();
    bad_ws.workspace_id = "...///...".to_string();
    assert!(SeatlingClient::new(bad_ws).is_err());

    let mut bad_prod = base_cfg.clone();
    bad_prod.product_id = "".to_string();
    assert!(SeatlingClient::new(bad_prod).is_err());

    let mut too_many_keys = base_cfg;
    for i in 0..65 {
        too_many_keys
            .public_keys
            .insert(format!("kid_{}", i), vk_b64.clone());
    }
    assert!(SeatlingClient::new(too_many_keys).is_err());
}
