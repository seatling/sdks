use base64::Engine;
use seatling::jwt::{decode_and_verify_jwt, encode_eddsa_jwt, JwtHeader};
use seatling::types::{
    ActivationPopClaims, HeartbeatAckClaims, LicenseJwtClaims, SeatlingConfig, StatusCode,
};
use seatling::verifier::TokenVerifier;
use seatling::SeatlingClient;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

struct MockRoute {
    path: String,
    status_code: u16,
    status_text: &'static str,
    response_body: String,
}

struct MockHttpServer {
    port: u16,
    routes: Arc<Mutex<Vec<MockRoute>>>,
    captured_bodies: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockHttpServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
        listener
            .set_nonblocking(true)
            .expect("set nonblocking listener");
        let port = listener.local_addr().unwrap().port();

        let routes = Arc::new(Mutex::new(Vec::<MockRoute>::new()));
        let captured_bodies = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let r_clone = Arc::clone(&routes);
        let c_clone = Arc::clone(&captured_bodies);
        let s_clone = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            while !s_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut buffer = Vec::new();
                        let mut chunk = [0u8; 1024];
                        let mut content_len = 0usize;
                        let mut header_end_pos = 0usize;

                        // Read request headers
                        while let Ok(n) = stream.read(&mut chunk) {
                            if n == 0 {
                                break;
                            }
                            buffer.extend_from_slice(&chunk[..n]);

                            // Look for \r\n\r\n
                            if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                                header_end_pos = pos + 4;
                                let header_str = String::from_utf8_lossy(&buffer[..pos]);
                                for line in header_str.lines() {
                                    if line.to_lowercase().starts_with("content-length:") {
                                        if let Some(val) = line.split(':').nth(1) {
                                            content_len = val.trim().parse::<usize>().unwrap_or(0);
                                        }
                                    }
                                }
                                break;
                            }
                        }

                        // Read remaining body
                        while buffer.len() < header_end_pos + content_len {
                            match stream.read(&mut chunk) {
                                Ok(n) if n > 0 => buffer.extend_from_slice(&chunk[..n]),
                                _ => break,
                            }
                        }

                        let header_part = String::from_utf8_lossy(&buffer[..header_end_pos]);
                        let first_line = header_part.lines().next().unwrap_or_default();
                        let req_path = first_line.split_whitespace().nth(1).unwrap_or_default();

                        let body_part = if buffer.len() >= header_end_pos {
                            String::from_utf8_lossy(&buffer[header_end_pos..]).to_string()
                        } else {
                            String::new()
                        };

                        c_clone.lock().unwrap().push(body_part);

                        // Find matching route
                        let (code, text, resp_body) = {
                            let r_lock = r_clone.lock().unwrap();
                            if let Some(route) = r_lock.iter().find(|r| r.path == req_path) {
                                (
                                    route.status_code,
                                    route.status_text,
                                    route.response_body.clone(),
                                )
                            } else {
                                (
                                    500,
                                    "Internal Server Error",
                                    "{\"error\":\"unhandled route\"}".to_string(),
                                )
                            }
                        };

                        let response = format!(
                            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                            code,
                            text,
                            resp_body.len(),
                            resp_body
                        );

                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        });

        Self {
            port,
            routes,
            captured_bodies,
            stop,
            handle: Some(handle),
        }
    }

    fn set_route(
        &self,
        path: &str,
        status_code: u16,
        status_text: &'static str,
        response_body: String,
    ) {
        let mut r = self.routes.lock().unwrap();
        r.retain(|entry| entry.path != path);
        r.push(MockRoute {
            path: path.to_string(),
            status_code,
            status_text,
            response_body,
        });
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for MockHttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[test]
fn test_client_activation_success_and_error_codes() {
    let tmp_dir = format!(
        "{}/seatling_net_test_{}",
        std::env::temp_dir().display(),
        std::process::id()
    );

    let workspace_sk = ed25519_dalek::SigningKey::from_bytes(&[101u8; 32]);
    let workspace_vk = workspace_sk.verifying_key();
    let workspace_vk_b64 =
        base64::engine::general_purpose::STANDARD.encode(workspace_vk.as_bytes());

    let mut public_keys = std::collections::HashMap::new();
    public_keys.insert("ws_2026_test".to_string(), workspace_vk_b64);

    let server = MockHttpServer::start();

    let cfg = SeatlingConfig {
        workspace_id: "ws_net_rust".to_string(),
        product_id: "prod_net_rust".to_string(),
        public_keys,
        app_version: "1.0.0".to_string(),
        api_base_url: server.url(),
        heartbeat_interval_seconds: 14400,
        storage_dir: Some(tmp_dir.clone()),
    };

    let client = SeatlingClient::new(cfg).expect("client creation");
    assert_eq!(client.initialize().status, StatusCode::NotActivated);
    assert!(!client.is_authorized());

    // 1. Error: 403 VERSION_NOT_ENTITLED
    server.set_route(
        "/v1/licenses/activate",
        403,
        "Forbidden",
        serde_json::json!({
            "code": "VERSION_NOT_ENTITLED",
            "message": "App version 1.0.0 is not entitled",
            "portal_url": "https://portal.seatling.com/upgrade"
        })
        .to_string(),
    );

    let res_ver = client.activate("SEAT-OLD-VER");
    assert!(!res_ver.success);
    assert_eq!(res_ver.status, StatusCode::VersionCeilingExceeded);
    assert_eq!(
        res_ver.portal_url.as_deref(),
        Some("https://portal.seatling.com/upgrade")
    );

    // 2. Error: 403 KEY_REVOKED_UPDATE_REQUIRED
    server.set_route(
        "/v1/licenses/activate",
        403,
        "Forbidden",
        serde_json::json!({
            "code": "KEY_REVOKED_UPDATE_REQUIRED",
            "message": "Key revoked",
            "portal_url": "https://portal.seatling.com/update"
        })
        .to_string(),
    );

    let res_key = client.activate("SEAT-REVOKED-KEY");
    assert!(!res_key.success);
    assert_eq!(res_key.status, StatusCode::KeyRevokedUpdateRequired);

    // 3. Error: 403 SEATS_EXHAUSTED
    server.set_route(
        "/v1/licenses/activate",
        403,
        "Forbidden",
        serde_json::json!({
            "code": "SEATS_EXHAUSTED",
            "message": "Seat quota exhausted",
            "portal_url": "https://portal.seatling.com/seats",
            "buyer_email": "b***@example.com",
            "seats_active": 5,
            "seat_limit": 5
        })
        .to_string(),
    );

    let res_seats = client.activate("SEAT-EXHAUSTED");
    assert!(!res_seats.success);
    assert_eq!(res_seats.status, StatusCode::SeatsExhausted);
    assert_eq!(res_seats.buyer_email.as_deref(), Some("b***@example.com"));
    assert_eq!(res_seats.seats_active, Some(5));

    // 4. Error: 409 REQUIRES_PORTAL_DEACTIVATION
    server.set_route(
        "/v1/licenses/activate",
        409,
        "Conflict",
        serde_json::json!({
            "code": "REQUIRES_PORTAL_DEACTIVATION",
            "message": "Rotation limit reached",
            "portal_url": "https://portal.seatling.com/manage"
        })
        .to_string(),
    );

    let res_portal = client.activate("SEAT-ROTATION-LIMIT");
    assert!(!res_portal.success);
    assert_eq!(res_portal.status, StatusCode::RequiresPortalDeactivation);

    // 5. Success: Valid 200 OK activation
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Read client keystore public key from storage
    let storage = seatling::StorageManager::new("ws_net_rust", "prod_net_rust", Some(&tmp_dir));
    let keystore = seatling::HardwareSealedKeystore::load_or_generate(&storage);
    let dev_pub_b64 = keystore.public_key_base64();
    let current_hwid = seatling::HWIDCollector::get_hwid();

    let mut entitlements = std::collections::HashMap::new();
    entitlements.insert("pro_dsp".to_string(), serde_json::json!(true));
    entitlements.insert("voices".to_string(), serde_json::json!(64));

    let license_claims = LicenseJwtClaims {
        iss: "seatling".to_string(),
        sub: "SEAT-VALID-KEY-1234".to_string(),
        aud: "ws_net_rust".to_string(),
        product_id: "prod_net_rust".to_string(),
        seat_id: "seat_rust_01".to_string(),
        masked_key: Some("SEAT-****-1234".to_string()),
        buyer_email: Some("pro@example.com".to_string()),
        hwid: current_hwid,
        device_key: Some(dev_pub_b64),
        app_version: "1.0.0".to_string(),
        iat: now,
        nbf: Some(now),
        exp: now + 14 * 86400,
        offline_grace_days: Some(14),
        status: "active".to_string(),
        entitlements,
    };

    let license_header = JwtHeader::new("seatling-license+jwt", Some("ws_2026_test"));
    let license_token = encode_eddsa_jwt(&license_header, &license_claims, &workspace_sk).unwrap();

    server.set_route(
        "/v1/licenses/activate",
        200,
        "OK",
        serde_json::json!({
            "token": license_token
        })
        .to_string(),
    );

    let res_act = client.activate("SEAT-VALID-KEY-1234");
    assert!(res_act.success);
    assert_eq!(res_act.status, StatusCode::Ok);
    assert_eq!(res_act.seat_id.as_deref(), Some("seat_rust_01"));

    // Verify cache updated and authorized
    assert!(client.is_authorized());
    assert!(client.is_valid());
    assert_eq!(client.status(), StatusCode::Ok);
    assert!(client.get_entitlement_bool("pro_dsp", false));
    assert_eq!(client.get_entitlement_i64("voices", 1), 64);

    // Verify PoP JWT was received by server
    let captured = server.captured_bodies.lock().unwrap();
    let last_req = captured.last().expect("last request");
    let json_val: serde_json::Value = serde_json::from_str(last_req).expect("parse json");
    let pop_token = json_val["token"].as_str().expect("token field");

    let device_vk =
        TokenVerifier::parse_verifying_key_base64(&keystore.public_key_base64()).unwrap();
    let (pop_header, pop_claims) =
        decode_and_verify_jwt::<ActivationPopClaims, _>(pop_token, |_| Ok(device_vk)).unwrap();
    assert_eq!(pop_header.typ, "seatling-activate-pop+jwt");
    assert_eq!(pop_claims.sub, "SEAT-VALID-KEY-1234");
    assert_eq!(pop_claims.app_version, "1.0.0");

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_client_heartbeat_and_seat_locking() {
    let tmp_dir = format!(
        "{}/seatling_hb_rust_test_{}",
        std::env::temp_dir().display(),
        std::process::id()
    );

    let workspace_sk = ed25519_dalek::SigningKey::from_bytes(&[102u8; 32]);
    let workspace_vk = workspace_sk.verifying_key();
    let workspace_vk_b64 =
        base64::engine::general_purpose::STANDARD.encode(workspace_vk.as_bytes());

    let mut public_keys = std::collections::HashMap::new();
    public_keys.insert("ws_2026_test".to_string(), workspace_vk_b64);

    let server = MockHttpServer::start();

    let storage = seatling::StorageManager::new("ws_net_rust", "prod_net_rust", Some(&tmp_dir));
    let keystore = seatling::HardwareSealedKeystore::load_or_generate(&storage);
    let dev_pub_b64 = keystore.public_key_base64();
    let current_hwid = seatling::HWIDCollector::get_hwid();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Create and save valid initial lease
    let license_claims = LicenseJwtClaims {
        iss: "seatling".to_string(),
        sub: "SEAT-HB-TEST".to_string(),
        aud: "ws_net_rust".to_string(),
        product_id: "prod_net_rust".to_string(),
        seat_id: "seat_hb_01".to_string(),
        masked_key: Some("SEAT-****-TEST".to_string()),
        buyer_email: Some("pro@example.com".to_string()),
        hwid: current_hwid,
        device_key: Some(dev_pub_b64),
        app_version: "1.0.0".to_string(),
        iat: now,
        nbf: Some(now),
        exp: now + 14 * 86400,
        offline_grace_days: Some(14),
        status: "active".to_string(),
        entitlements: std::collections::HashMap::new(),
    };

    let license_header = JwtHeader::new("seatling-license+jwt", Some("ws_2026_test"));
    let license_token = encode_eddsa_jwt(&license_header, &license_claims, &workspace_sk).unwrap();
    storage.write_lease(&license_token).unwrap();

    let cfg = SeatlingConfig {
        workspace_id: "ws_net_rust".to_string(),
        product_id: "prod_net_rust".to_string(),
        public_keys,
        app_version: "1.0.0".to_string(),
        api_base_url: server.url(),
        heartbeat_interval_seconds: 14400,
        storage_dir: Some(tmp_dir.clone()),
    };

    let client = SeatlingClient::new(cfg).unwrap();
    assert_eq!(client.initialize().status, StatusCode::Ok);
    assert!(client.is_authorized());

    // 1. Successful heartbeat: server returns ack with echoed nonce
    // We register a route that reads challenge nonce and replies with valid ack
    let server_routes = Arc::clone(&server.routes);
    let server_captured = Arc::clone(&server.captured_bodies);
    let ws_sk_clone = ed25519_dalek::SigningKey::from_bytes(&[102u8; 32]);

    // Spawn a quick handler thread that updates route when challenge is posted
    thread::spawn(move || {
        for _ in 0..100 {
            let captured = server_captured.lock().unwrap().clone();
            if let Some(req_body) = captured.last() {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(req_body) {
                    if let Some(challenge_tok) = json["token"].as_str() {
                        let parts: Vec<&str> = challenge_tok.split('.').collect();
                        if parts.len() == 3 {
                            if let Ok(bytes) =
                                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])
                            {
                                if let Ok(claims) =
                                    serde_json::from_slice::<serde_json::Value>(&bytes)
                                {
                                    if let Some(nonce) = claims["jti"].as_str() {
                                        let mut new_ents = std::collections::HashMap::new();
                                        new_ents
                                            .insert("hd_mode".to_string(), serde_json::json!(true));

                                        let ack_claims = HeartbeatAckClaims {
                                            iss: "seatling".to_string(),
                                            sub: "SEAT-HB-TEST".to_string(),
                                            aud: "ws_net_rust".to_string(),
                                            product_id: "prod_net_rust".to_string(),
                                            seat_id: "seat_hb_01".to_string(),
                                            status: "active".to_string(),
                                            iat: now,
                                            exp: now + 20 * 86400,
                                            jti: nonce.to_string(),
                                            entitlements: new_ents,
                                        };
                                        let ack_header = JwtHeader::new(
                                            "seatling-heartbeat-ack+jwt",
                                            Some("ws_2026_test"),
                                        );
                                        let ack_token = encode_eddsa_jwt(
                                            &ack_header,
                                            &ack_claims,
                                            &ws_sk_clone,
                                        )
                                        .unwrap();

                                        let mut r = server_routes.lock().unwrap();
                                        r.retain(|entry| entry.path != "/v1/licenses/heartbeat");
                                        r.push(MockRoute {
                                            path: "/v1/licenses/heartbeat".to_string(),
                                            status_code: 200,
                                            status_text: "OK",
                                            response_body:
                                                serde_json::json!({ "token": ack_token })
                                                    .to_string(),
                                        });
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    });

    let hb_status = client.heartbeat_now();
    assert_eq!(hb_status.status, StatusCode::Ok);
    assert!(client.is_authorized());

    // 2. Server locked status revokes authorization immediately
    let locked_claims = HeartbeatAckClaims {
        iss: "seatling".to_string(),
        sub: "SEAT-HB-TEST".to_string(),
        aud: "ws_net_rust".to_string(),
        product_id: "prod_net_rust".to_string(),
        seat_id: "seat_hb_01".to_string(),
        status: "locked".to_string(),
        iat: now,
        exp: now + 14 * 86400,
        jti: "dummy_nonce".to_string(),
        entitlements: std::collections::HashMap::new(),
    };
    // Update route to return locked
    server.set_route(
        "/v1/licenses/heartbeat",
        200,
        "OK",
        serde_json::json!({
            "token": encode_eddsa_jwt(
                &JwtHeader::new("seatling-heartbeat-ack+jwt", Some("ws_2026_test")),
                &locked_claims,
                &workspace_sk
            ).unwrap(),
            "portal_url": "https://portal.seatling.com/locked"
        })
        .to_string(),
    );

    // 3. Network outage (HTTP 500) preserves offline validity
    server.set_route(
        "/v1/licenses/heartbeat",
        500,
        "Internal Error",
        "{}".to_string(),
    );

    let status_offline = client.heartbeat_now();
    assert!(status_offline.is_authorized);
    assert!(client.is_authorized());

    // 4. Client deactivation
    assert!(client.deactivate().is_ok());
    assert!(!client.is_authorized());
    assert_eq!(client.status(), StatusCode::NotActivated);
    assert!(storage.read_lease().is_none());

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
