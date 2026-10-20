use base64::Engine;
use seatling::cache::{LeaseSnapshot, StateAndEntitlementCache};
use seatling::hwid::HWIDCollector;
use seatling::jwt::{decode_and_verify_jwt, encode_eddsa_jwt, JwtHeader};
use seatling::keystore::HardwareSealedKeystore;
use seatling::storage::StorageManager;
use seatling::types::{
    ActivationPopClaims, HeartbeatChallengeClaims, LicenseJwtClaims, SeatlingConfig, StatusCode,
};
use seatling::verifier::TokenVerifier;
use seatling::SeatlingClient;
use std::time::Instant;

#[test]
fn test_hwid_components_and_quorum() {
    let components = HWIDCollector::get_components();
    assert_eq!(components.cpu.len(), 64);
    assert_eq!(components.mobo.len(), 64);
    assert_eq!(components.disk.len(), 64);
    assert_eq!(components.os_uuid.len(), 64);

    let hwid = HWIDCollector::get_hwid();
    assert_eq!(hwid.len(), 64);

    // 4 of 4 (100 pts >= 70)
    assert_eq!(HWIDCollector::weighted_score(&components, &components), 100);
    assert!(HWIDCollector::fuzzy_match_quorum(&components, &components));

    // Mobo(35) + CPU(25) + Disk(20) = 80 pts >= 70 (PASS)
    let mut c_os_swapped = components.clone();
    c_os_swapped.os_uuid =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    assert_eq!(
        HWIDCollector::weighted_score(&components, &c_os_swapped),
        80
    );
    assert!(HWIDCollector::fuzzy_match_quorum(
        &components,
        &c_os_swapped
    ));

    // CPU(25) + Disk(20) + OS(20) = 65 pts < 70 (Mobo swapped: FAIL)
    let mut c_mobo_swapped = components.clone();
    c_mobo_swapped.mobo =
        "1111111111111111111111111111111111111111111111111111111111111111".to_string();
    assert_eq!(
        HWIDCollector::weighted_score(&components, &c_mobo_swapped),
        65
    );
    assert!(!HWIDCollector::fuzzy_match_quorum(
        &components,
        &c_mobo_swapped
    ));
}

#[test]
fn test_v6_keystore_sealing_and_jwt_signing() {
    let tmp_dir = format!(
        "{}/seatling_keystore_test_{}",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let storage = StorageManager::new("ws_test", "prod_test", Some(&tmp_dir));
    let keystore = HardwareSealedKeystore::load_or_generate(&storage);

    let pub_key_b64 = keystore.public_key_base64();
    assert!(!pub_key_b64.is_empty());

    let components = HWIDCollector::get_components();
    let supported_kids = vec!["ws_demo_2026_v1".to_string()];

    // 1. Activation PoP JWT
    let pop_jwt = keystore
        .sign_activation_pop_jwt(
            "SEAT-1111",
            "mock_hwid",
            components,
            "1.0.0",
            "https://api.seatling.com",
            &supported_kids,
            1729382400,
            "test_nonce_pop",
        )
        .expect("sign PoP JWT");
    assert!(!pop_jwt.is_empty());

    // Verify PoP JWT against device public key
    let device_vk = TokenVerifier::parse_verifying_key_base64(&pub_key_b64).expect("valid vk");
    let (header, claims) =
        decode_and_verify_jwt::<ActivationPopClaims, _>(&pop_jwt, |_| Ok(device_vk))
            .expect("verify PoP JWT");
    assert_eq!(header.alg, "EdDSA");
    assert_eq!(header.typ, "seatling-activate-pop+jwt");
    assert_eq!(claims.sub, "SEAT-1111");
    assert_eq!(claims.hwid, "mock_hwid");
    assert_eq!(claims.supported_kids, vec!["ws_demo_2026_v1"]);
    assert_eq!(claims.jti, "test_nonce_pop");

    // 2. Heartbeat Challenge JWT
    let hb_jwt = keystore
        .sign_heartbeat_challenge_jwt(
            "SEAT-1111",
            "seat_01",
            "mock_hwid",
            "session_12345",
            "1.0.0",
            "https://api.seatling.com",
            &supported_kids,
            1729382400,
            "test_nonce_hb",
        )
        .expect("sign HB challenge JWT");
    assert!(!hb_jwt.is_empty());

    let (hb_header, hb_claims) =
        decode_and_verify_jwt::<HeartbeatChallengeClaims, _>(&hb_jwt, |_| Ok(device_vk))
            .expect("verify HB JWT");
    assert_eq!(hb_header.typ, "seatling-heartbeat-challenge+jwt");
    assert_eq!(hb_claims.seat_id, "seat_01");
    assert_eq!(hb_claims.supported_kids, vec!["ws_demo_2026_v1"]);
    assert_eq!(hb_claims.jti, "test_nonce_hb");

    // Subsequent reload unseals identical key
    let keystore2 = HardwareSealedKeystore::load_or_generate(&storage);
    assert_eq!(pub_key_b64, keystore2.public_key_base64());

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_v6_claim_isolation_and_key_matching() {
    let dummy_sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let dummy_vk = dummy_sk.verifying_key();
    let dummy_vk_b64 = base64::engine::general_purpose::STANDARD.encode(dummy_vk.as_bytes());

    let mut keys_map = std::collections::HashMap::new();
    keys_map.insert("custom_kid_1".to_string(), dummy_vk_b64);
    let verifier = TokenVerifier::new(&keys_map).expect("verifier creation");

    let header = JwtHeader::new("seatling-license+jwt", Some("custom_kid_1"));
    let valid_claims = LicenseJwtClaims {
        iss: "seatling".to_string(),
        sub: "SEAT-TEST-1234".to_string(),
        aud: "ws_my_studio".to_string(),
        product_id: "prod_my_synth".to_string(),
        seat_id: "seat_01".to_string(),
        masked_key: Some("SEAT-****-1234".to_string()),
        buyer_email: Some("buyer@example.com".to_string()),
        hwid: "mock_hwid".to_string(),
        device_key: None,
        app_version: "2.0.0".to_string(),
        iat: 1729382400,
        nbf: Some(1729382400),
        exp: 1729382400 + 14 * 86400,
        offline_grace_days: Some(14),
        status: "active".to_string(),
        entitlements: std::collections::HashMap::new(),
    };

    let token = encode_eddsa_jwt(&header, &valid_claims, &dummy_sk).expect("encode jwt");

    // 1. Matches expected workspace & product
    let res = verifier.verify_license_token(&token, "ws_my_studio", "prod_my_synth");
    assert!(res.is_ok());

    // 2. Mismatch workspace -> InvalidProductOrWorkspace
    let res_ws_mismatch =
        verifier.verify_license_token(&token, "ws_other_creator", "prod_my_synth");
    assert_eq!(
        res_ws_mismatch.unwrap_err().0,
        StatusCode::InvalidProductOrWorkspace
    );

    // 3. Mismatch product -> InvalidProductOrWorkspace
    let res_prod_mismatch =
        verifier.verify_license_token(&token, "ws_my_studio", "prod_other_synth");
    assert_eq!(
        res_prod_mismatch.unwrap_err().0,
        StatusCode::InvalidProductOrWorkspace
    );

    // 4. Empty public_keys fails verifier creation
    let empty_map = std::collections::HashMap::new();
    assert!(TokenVerifier::new(&empty_map).is_err());

    // 5. Unrecognized kid rejected
    let unknown_header = JwtHeader::new("seatling-license+jwt", Some("unknown_kid_999"));
    let unknown_token =
        encode_eddsa_jwt(&unknown_header, &valid_claims, &dummy_sk).expect("encode jwt");
    assert_eq!(
        verifier
            .verify_license_token(&unknown_token, "ws_my_studio", "prod_my_synth")
            .unwrap_err()
            .0,
        StatusCode::TamperOrSignatureInvalid
    );

    // 6. V7 Base64URL and Standard Base64 key parsing support
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let raw_pk_bytes = dummy_vk.to_bytes();

    let b64url_no_pad = URL_SAFE_NO_PAD.encode(raw_pk_bytes);
    let b64url_pad = URL_SAFE.encode(raw_pk_bytes);
    let b64_std = STANDARD.encode(raw_pk_bytes);
    let b64_std_no_pad = STANDARD_NO_PAD.encode(raw_pk_bytes);

    let parsed_url_no_pad = TokenVerifier::parse_verifying_key_base64(&b64url_no_pad).unwrap();
    let parsed_url_pad = TokenVerifier::parse_verifying_key_base64(&b64url_pad).unwrap();
    let parsed_std = TokenVerifier::parse_verifying_key_base64(&b64_std).unwrap();
    let parsed_std_no_pad = TokenVerifier::parse_verifying_key_base64(&b64_std_no_pad).unwrap();

    assert_eq!(parsed_url_no_pad, dummy_vk);
    assert_eq!(parsed_url_pad, dummy_vk);
    assert_eq!(parsed_std, dummy_vk);
    assert_eq!(parsed_std_no_pad, dummy_vk);

    // Verify token verification using Base64URL configured keys
    let mut v7_keys = std::collections::HashMap::new();
    v7_keys.insert("ws_2027_v1".to_string(), b64url_no_pad);
    let v7_verifier = TokenVerifier::new(&v7_keys).unwrap();

    let v7_header = JwtHeader::new("seatling-license+jwt", Some("ws_2027_v1"));
    let v7_token = encode_eddsa_jwt(&v7_header, &valid_claims, &dummy_sk).unwrap();
    assert!(v7_verifier
        .verify_license_token(&v7_token, "ws_my_studio", "prod_my_synth")
        .is_ok());
}

#[test]
fn test_lock_free_cache_latency_benchmark() {
    let cache = StateAndEntitlementCache::new();
    let snap = LeaseSnapshot {
        status: StatusCode::Ok,
        is_authorized: true,
        ..Default::default()
    };
    cache.update(snap);

    let iterations = 100_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let auth = cache.is_authorized();
        assert!(auth);
    }
    let duration = start.elapsed();
    let avg_ns = duration.as_nanos() as f64 / iterations as f64;

    println!(
        "[Rust Benchmark] avg {:.2} ns per is_authorized() call",
        avg_ns
    );
    assert!(
        avg_ns < 10_000.0,
        "Latency exceeded 10,000ns: {:.2}ns",
        avg_ns
    );
}

#[test]
fn test_client_lifecycle_not_activated() {
    let tmp_dir = format!(
        "{}/seatling_client_test_{}",
        std::env::temp_dir().display(),
        std::process::id()
    );

    let mut public_keys = std::collections::HashMap::new();
    public_keys.insert(
        "demo_kid".to_string(),
        "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".to_string(),
    );

    let cfg = SeatlingConfig {
        workspace_id: "ws_demo".to_string(),
        product_id: "prod_demo".to_string(),
        public_keys,
        app_version: "1.0.0".to_string(),
        api_base_url: "https://api.seatling.com".to_string(),
        heartbeat_interval_seconds: 14400,
        storage_dir: Some(tmp_dir.clone()),
    };

    let client = SeatlingClient::new(cfg).expect("client creation");
    assert_eq!(client.session_id().len(), 32);
    let status = client.initialize();
    assert_eq!(status.status, StatusCode::NotActivated);
    assert!(!client.is_authorized());
    assert!(!client.is_valid());
    assert_eq!(client.status(), StatusCode::NotActivated);
    assert!(!client.is_valid_blocking(std::time::Duration::from_millis(50)));
    assert_eq!(
        client
            .status_blocking(std::time::Duration::from_millis(50))
            .status,
        StatusCode::NotActivated
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_v3_keystore_timeline_and_anti_clock_rollback() {
    let tmp_dir = format!(
        "{}/seatling_v3_keystore_test_{}",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let storage = StorageManager::new("ws_v3", "prod_v3", Some(&tmp_dir));
    let mut keystore = HardwareSealedKeystore::load_or_generate(&storage);

    // Verify 104-byte packed format (V4)
    let raw_bytes = keystore.record().to_bytes();
    assert_eq!(raw_bytes.len(), 104);

    let base_time = 1_700_000_000i64;
    let grace_duration = 14 * 86400i64; // 14 days

    keystore.update_timeline(&storage, base_time, grace_duration);
    assert_eq!(keystore.record().last_validated_at_utc, base_time);
    assert_eq!(keystore.record().high_water_mark_utc, base_time);
    assert_eq!(keystore.record().grace_duration_seconds, grace_duration);

    // 1. Advance high water mark to base_time + 10,000
    keystore.advance_high_water_mark(&storage, base_time + 10_000);
    assert_eq!(keystore.record().high_water_mark_utc, base_time + 10_000);

    // 2. Normal forward time within grace
    let status = keystore.evaluate_clock_and_grace(base_time + 10_005);
    assert_eq!(status, StatusCode::Ok);

    // 3. Backward drift within 300s NTP tolerance (e.g. 200s behind HWM)
    let status_jitter = keystore.evaluate_clock_and_grace(base_time + 10_000 - 200);
    assert_eq!(status_jitter, StatusCode::Ok);

    // 4. Backward drift exceeding 300s (e.g. 301s behind HWM) -> TimeTamperDetected
    let status_tamper = keystore.evaluate_clock_and_grace(base_time + 10_000 - 301);
    assert_eq!(status_tamper, StatusCode::TimeTamperDetected);

    // 5. Normal time past grace duration -> OfflineGraceExpired
    let status_expired = keystore.evaluate_clock_and_grace(base_time + grace_duration + 1);
    assert_eq!(status_expired, StatusCode::OfflineGraceExpired);

    // 6. Resealed keystore reload persists timeline
    let reloaded = HardwareSealedKeystore::load_or_generate(&storage);
    assert_eq!(reloaded.record().high_water_mark_utc, base_time + 10_000);
    assert_eq!(reloaded.record().grace_duration_seconds, grace_duration);

    // 7. Authoritative server heartbeat heals clock rollback
    let new_server_time = base_time + 50_000;
    keystore.update_timeline(&storage, new_server_time, grace_duration);
    assert_eq!(keystore.record().high_water_mark_utc, new_server_time);
    assert_eq!(keystore.record().last_validated_at_utc, new_server_time);
    assert_eq!(
        keystore.evaluate_clock_and_grace(new_server_time),
        StatusCode::Ok
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_device_binding_and_revoked_status_rejection() {
    let dummy_sk = ed25519_dalek::SigningKey::from_bytes(&[77u8; 32]);
    let dummy_vk = dummy_sk.verifying_key();
    let dummy_vk_b64 = base64::engine::general_purpose::STANDARD.encode(dummy_vk.as_bytes());

    let device_sk = ed25519_dalek::SigningKey::from_bytes(&[88u8; 32]);
    let device_vk = device_sk.verifying_key();
    let device_vk_b64 = base64::engine::general_purpose::STANDARD.encode(device_vk.as_bytes());

    let other_device_sk = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
    let other_device_vk = other_device_sk.verifying_key();

    let mut keys_map = std::collections::HashMap::new();
    keys_map.insert("kid_bind_1".to_string(), dummy_vk_b64);
    let verifier = TokenVerifier::new(&keys_map).expect("verifier creation");

    let header = JwtHeader::new("seatling-license+jwt", Some("kid_bind_1"));
    let base_claims = LicenseJwtClaims {
        iss: "seatling".to_string(),
        sub: "SEAT-BIND-1234".to_string(),
        aud: "ws_studio".to_string(),
        product_id: "prod_plugin".to_string(),
        seat_id: "seat_01".to_string(),
        masked_key: None,
        buyer_email: None,
        hwid: "expected_hwid_hash".to_string(),
        device_key: Some(device_vk_b64),
        app_version: "1.0.0".to_string(),
        iat: 1_729_382_400,
        nbf: None,
        exp: 1_729_382_400 + 86400,
        offline_grace_days: Some(1),
        status: "active".to_string(),
        entitlements: std::collections::HashMap::new(),
    };

    let token = encode_eddsa_jwt(&header, &base_claims, &dummy_sk).unwrap();

    // 1. Matching HWID and device_key succeeds
    assert!(verifier
        .verify_license_token_bound(
            &token,
            "ws_studio",
            "prod_plugin",
            "expected_hwid_hash",
            &device_vk,
        )
        .is_ok());

    // 2. Mismatched HWID rejected
    assert_eq!(
        verifier
            .verify_license_token_bound(
                &token,
                "ws_studio",
                "prod_plugin",
                "wrong_hwid_hash",
                &device_vk,
            )
            .unwrap_err()
            .0,
        StatusCode::TamperOrSignatureInvalid
    );

    // 3. Mismatched device_key rejected
    assert_eq!(
        verifier
            .verify_license_token_bound(
                &token,
                "ws_studio",
                "prod_plugin",
                "expected_hwid_hash",
                &other_device_vk,
            )
            .unwrap_err()
            .0,
        StatusCode::TamperOrSignatureInvalid
    );

    // 4. Suspended status rejected
    let mut suspended_claims = base_claims;
    suspended_claims.status = "suspended".to_string();
    let suspended_token = encode_eddsa_jwt(&header, &suspended_claims, &dummy_sk).unwrap();
    assert_eq!(
        verifier
            .verify_license_token(&suspended_token, "ws_studio", "prod_plugin")
            .unwrap_err()
            .0,
        StatusCode::LicenseSuspendedOrRevoked
    );
}

#[test]
fn test_dpapi_keystore_sealing_and_tamper_rejection() {
    let tmp_dir = format!(
        "{}/seatling_dpapi_test_{}",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let storage = StorageManager::new("ws_dpapi", "prod_dpapi", Some(&tmp_dir));
    let keystore = HardwareSealedKeystore::load_or_generate(&storage);
    let pub_key_b64 = keystore.public_key_base64();

    // Verify keystore.bin was written and inspect StoredKeystoreFile
    let content = storage
        .read_keystore()
        .expect("keystore must exist on disk");
    let mut stored: seatling::types::StoredKeystoreFile =
        serde_json::from_str(&content).expect("parse stored keystore");

    #[cfg(target_os = "windows")]
    {
        // On Windows, dpapi_blob must be present and non-empty
        assert!(stored.dpapi_blob.is_some());
        let dpapi_blob = stored.dpapi_blob.as_ref().unwrap();
        assert!(!dpapi_blob.is_empty());

        // Subsequent load unseals successfully with matching public key
        let reloaded = HardwareSealedKeystore::load_or_generate(&storage);
        assert_eq!(reloaded.public_key_base64(), pub_key_b64);

        // Tamper with dpapi_blob (simulating key copied to foreign machine or altered)
        stored.dpapi_blob =
            Some(base64::engine::general_purpose::STANDARD.encode(b"invalid_dpapi_bytes"));
        storage
            .write_keystore(&serde_json::to_string_pretty(&stored).unwrap())
            .expect("write tampered keystore");

        // Reloading with corrupted dpapi_blob must reject unsealing and generate a fresh keypair
        let tampered_reloaded = HardwareSealedKeystore::load_or_generate(&storage);
        assert_ne!(
            tampered_reloaded.public_key_base64(),
            pub_key_b64,
            "Tampered DPAPI blob must not unseal original key"
        );
    }

    #[cfg(not(target_os = "windows"))]
    {
        assert!(stored.dpapi_blob.is_none());
        let reloaded = HardwareSealedKeystore::load_or_generate(&storage);
        assert_eq!(reloaded.public_key_base64(), pub_key_b64);
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
