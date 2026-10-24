#include <iostream>
#include <fstream>
#include <cassert>
#include <chrono>
#include <string>
#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#endif
#include "seatling/seatling.hpp"

static int g_test_count = 0;
static int g_fail_count = 0;

#define RUN_TEST(name) \
    do { \
        g_test_count++; \
        std::cout << "Running test: " << #name << " ... "; \
        try { \
            name(); \
            std::cout << "PASSED" << std::endl; \
        } catch (const std::exception& e) { \
            g_fail_count++; \
            std::cout << "FAILED (" << e.what() << ")" << std::endl; \
        } catch (...) { \
            g_fail_count++; \
            std::cout << "FAILED (unknown error)" << std::endl; \
        } \
    } while(0)

// 32-byte valid Ed25519 public key base64 for testing
static const char* TEST_PUB_KEY = "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=";

// 1. HWID test
void test_hwid() {
    std::string hwid = seatling::SeatlingClient::get_hwid();
    if (hwid.length() != 64) {
        throw std::runtime_error("HWID must be 64 characters hex SHA-256, got len: " + std::to_string(hwid.length()));
    }
}

// 2. Client initialization on empty directory
void test_client_lifecycle_not_activated() {
    seatling::SeatlingConfig cfg;
    cfg.workspace_id = "ws_test";
    cfg.product_id = "prod_test";
    cfg.public_keys["test_kid"] = TEST_PUB_KEY;
    cfg.app_version = "1.0.0";
    cfg.storage_dir = "test_seatling_storage_temp";

    seatling::SeatlingClient client(cfg);
    std::string session_id = client.get_session_id();
    if (session_id.length() != 32) {
        throw std::runtime_error("Expected 32-character session_id, got len: " + std::to_string(session_id.length()));
    }

    seatling::StatusCode status = client.initialize();

    if (status != seatling::StatusCode::NotActivated) {
        throw std::runtime_error("Expected StatusCode::NotActivated, got: " + std::string(seatling::status_to_string(status)));
    }

    if (client.is_authorized()) {
        throw std::runtime_error("Client must not be authorized when unactivated");
    }
}

// 3. Fast hot-path check latency benchmark (< 0.01ms / 10,000ns)
void test_lock_free_cache_latency_benchmark() {
    seatling::SeatlingConfig cfg;
    cfg.workspace_id = "ws_bench";
    cfg.product_id = "prod_bench";
    cfg.public_keys["test_kid"] = TEST_PUB_KEY;

    seatling::SeatlingClient client(cfg);
    client.initialize();

    const int iterations = 100000;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        bool auth = client.is_authorized();
        (void)auth;
    }

    auto end = std::chrono::high_resolution_clock::now();
    double total_ns = std::chrono::duration<double, std::nano>(end - start).count();
    double avg_ns = total_ns / static_cast<double>(iterations);

    std::cout << "[Benchmark: " << avg_ns << " ns/call] ";

    // Invariant: < 0.01ms (10,000ns)
    if (avg_ns >= 10000.0) {
        throw std::runtime_error("is_authorized latency exceeded 0.01ms threshold: " + std::to_string(avg_ns) + " ns");
    }
}

// 4. Entitlements default fallbacks
void test_entitlements_fallback() {
    seatling::SeatlingConfig cfg;
    cfg.workspace_id = "ws_ent";
    cfg.product_id = "prod_ent";
    cfg.public_keys["test_kid"] = TEST_PUB_KEY;

    seatling::SeatlingClient client(cfg);
    client.initialize();

    if (client.get_entitlement_bool("feature_x", false) != false) {
        throw std::runtime_error("Boolean entitlement default mismatch");
    }
    if (client.get_entitlement_bool("feature_x", true) != true) {
        throw std::runtime_error("Boolean entitlement default mismatch");
    }
    if (client.get_entitlement_i64("export_limit", 42) != 42) {
        throw std::runtime_error("i64 entitlement default mismatch");
    }
    if (client.get_entitlement_f64("multiplier", 3.14) != 3.14) {
        throw std::runtime_error("f64 entitlement default mismatch");
    }
}

// 5. V3 Dual Query and TimeTamperDetected
void test_v3_dual_query() {
    seatling::SeatlingConfig cfg;
    cfg.workspace_id = "ws_v3";
    cfg.product_id = "prod_v3";
    cfg.public_keys["test_kid"] = TEST_PUB_KEY;
    cfg.storage_dir = "test_seatling_storage_v3";

    seatling::SeatlingClient client(cfg);
    client.initialize();

    // Lock-free queries (< 0.05ms)
    if (client.is_valid()) {
        throw std::runtime_error("client.is_valid() must be false for unactivated client");
    }
    if (client.status() != seatling::StatusCode::NotActivated) {
        throw std::runtime_error("client.status() must be NotActivated");
    }

    // Blocking queries
    if (client.is_valid_blocking(50)) {
        throw std::runtime_error("client.is_valid_blocking() must be false");
    }
    if (client.status_blocking(50) != seatling::StatusCode::NotActivated) {
        throw std::runtime_error("client.status_blocking() must be NotActivated");
    }

    // Verify TimeTamperDetected enum string
    std::string tamper_str = seatling::status_to_string(seatling::StatusCode::TimeTamperDetected);
    if (tamper_str != "TIME_TAMPER_DETECTED") {
        throw std::runtime_error("status_to_string(TimeTamperDetected) failed: " + tamper_str);
    }

    // Verify InvalidProductOrWorkspace enum string
    std::string invalid_str = seatling::status_to_string(seatling::StatusCode::InvalidProductOrWorkspace);
    if (invalid_str != "INVALID_PRODUCT_OR_WORKSPACE") {
        throw std::runtime_error("status_to_string(InvalidProductOrWorkspace) failed: " + invalid_str);
    }

    // Verify KeyRevokedUpdateRequired enum string
    std::string revoked_str = seatling::status_to_string(seatling::StatusCode::KeyRevokedUpdateRequired);
    if (revoked_str != "KEY_REVOKED_UPDATE_REQUIRED") {
        throw std::runtime_error("status_to_string(KeyRevokedUpdateRequired) failed: " + revoked_str);
    }
}

// 6. V6 Public Key Validation (rejection on empty keys, embedded NUL, or duplicate FFI keys)
void test_v6_rejection_on_empty_keys() {
    seatling::SeatlingConfig cfg;
    cfg.workspace_id = "ws_empty";
    cfg.product_id = "prod_empty";
    // public_keys left empty -> must throw std::runtime_error

    bool threw = false;
    try {
        seatling::SeatlingClient client(cfg);
    } catch (const std::runtime_error&) {
        threw = true;
    }

    if (!threw) {
        throw std::runtime_error("Expected SeatlingClient to throw on empty public_keys");
    }

    // Embedded NUL byte in workspace_id must throw
    seatling::SeatlingConfig nul_cfg;
    nul_cfg.workspace_id = std::string("ws_bad\0injected", 15);
    nul_cfg.product_id = "prod_empty";
    nul_cfg.public_keys["kid_1"] = TEST_PUB_KEY;
    bool nul_threw = false;
    try {
        seatling::SeatlingClient client(nul_cfg);
    } catch (const std::runtime_error&) {
        nul_threw = true;
    }
    if (!nul_threw) {
        throw std::runtime_error("Expected SeatlingClient to throw on embedded NUL byte");
    }

    // Duplicate kid entries at raw C-ABI level must fail closed (return nullptr)
    seatling_key_entry_t dup_entries[2] = {
        { "dup_kid", TEST_PUB_KEY },
        { "dup_kid", TEST_PUB_KEY }
    };
    seatling_config_t raw_cfg{};
    raw_cfg.workspace_id = "ws_dup";
    raw_cfg.product_id = "prod_dup";
    raw_cfg.public_keys = dup_entries;
    raw_cfg.public_keys_count = 2;
    raw_cfg.app_version = "1.0.0";
    if (::seatling_client_new(&raw_cfg) != nullptr) {
        throw std::runtime_error("Expected seatling_client_new to reject duplicate kid entries");
    }
}

// 7. V6 Specification Syntax Check (HARDWARE_ANCHOR_V6.md §7.1.1)
void test_v6_spec_syntax() {
    SeatlingConfig cfg1;
    cfg1.workspace_id = "ws_gumroad_creator";
    cfg1.product_id = "prod_synth_v1";
    cfg1.public_keys = {
        { "ws_gumroad_creator_2026_v1", TEST_PUB_KEY }
    };
    cfg1.app_version = "2.4.1";

    const auto seatling = Seatling::init(cfg1);
    if (seatling.status() != SeatlingStatus::NotActivated) {
        throw std::runtime_error("Expected NotActivated from Seatling::init");
    }

    SeatlingConfig cfg2;
    cfg2.workspace_id = "ws_enterprise_studio";
    cfg2.product_id = "prod_flagship_v1";
    cfg2.public_keys = {
        { "custom_2026_v1", TEST_PUB_KEY },
        { "custom_2027_v1", TEST_PUB_KEY }
    };
    cfg2.app_version = "1.0.0";

    const auto enterprise_seatling = Seatling::init(cfg2);
    if (enterprise_seatling.status() != SeatlingStatus::NotActivated) {
        throw std::runtime_error("Expected NotActivated from enterprise Seatling::init");
    }
}

// 8. V6 Weighted HWID Quorum Score Calculation
void test_v6_weighted_hwid_score() {
    uint32_t pass_score = ::seatling_hwid_weighted_score(
        "cpu_a", "mobo_a", "disk_a", "os_a",
        "cpu_a", "mobo_a", "disk_a", "os_b" // mobo(35) + cpu(25) + disk(20) = 80
    );
    if (pass_score != 80) {
        throw std::runtime_error("Expected 80 points, got: " + std::to_string(pass_score));
    }

    uint32_t fail_score = ::seatling_hwid_weighted_score(
        "cpu_a", "mobo_a", "disk_a", "os_a",
        "cpu_a", "mobo_b", "disk_a", "os_a" // cpu(25) + disk(20) + os(20) = 65 (mobo replaced)
    );
    if (fail_score != 65) {
        throw std::runtime_error("Expected 65 points, got: " + std::to_string(fail_score));
    }
}

// 9. V7 Base64URL-encoded Ed25519 public key in public_keys map (HARDWARE_ANCHOR_V7.md §7.1.1)
void test_v7_base64url_public_key() {
    seatling::SeatlingConfig cfg;
    cfg.workspace_id = "ws_v7_creator";
    cfg.product_id = "prod_v7";
    // Unpadded Base64URL format (RFC 4648 §5) containing '-' and '_' with no trailing '='
    cfg.public_keys = {
        { "ws_v7_creator_2026_v1", "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw" }
    };
    cfg.app_version = "2.4.1";
    cfg.storage_dir = "test_v7_storage_temp";

    seatling::SeatlingClient client(cfg);
    seatling::StatusCode status = client.initialize();
    if (status != seatling::StatusCode::NotActivated) {
        throw std::runtime_error("Expected NotActivated for valid Base64URL key on unactivated client");
    }
}

// 10. Invalid SemVer configuration rejection
void test_client_invalid_semver_rejection() {
    seatling::SeatlingConfig cfg;
    cfg.workspace_id = "ws_semver";
    cfg.product_id = "prod_semver";
    cfg.public_keys["kid_1"] = TEST_PUB_KEY;
    cfg.app_version = "invalid_semver_string";

    bool threw = false;
    try {
        seatling::SeatlingClient client(cfg);
    } catch (const std::runtime_error&) {
        threw = true;
    }

    if (!threw) {
        throw std::runtime_error("Expected SeatlingClient to throw on invalid app_version SemVer");
    }
}

// 11. Tampered / invalid lease on disk rejection
void test_client_tampered_lease_rejection() {
    std::string test_dir = "test_tampered_cpp_temp";
#if defined(_WIN32)
    _mkdir(test_dir.c_str());
#else
    mkdir(test_dir.c_str(), 0755);
#endif

    std::string lease_file = test_dir + "/lease.seatling";
    {
        std::ofstream ofs(lease_file);
        ofs << "corrupted.payload.garbage_signature";
    }

    seatling::SeatlingConfig cfg;
    cfg.workspace_id = "ws_tamper";
    cfg.product_id = "prod_tamper";
    cfg.public_keys["kid_1"] = TEST_PUB_KEY;
    cfg.app_version = "1.0.0";
    cfg.storage_dir = test_dir;

    seatling::SeatlingClient client(cfg);
    seatling::StatusCode status = client.initialize();

    if (status != seatling::StatusCode::TamperOrSignatureInvalid) {
        throw std::runtime_error("Expected TamperOrSignatureInvalid, got: " + std::string(seatling::status_to_string(status)));
    }

    if (client.is_authorized()) {
        throw std::runtime_error("Client must not be authorized when lease is corrupted");
    }
}

// 12. Client deactivation
void test_client_deactivate() {
    seatling::SeatlingConfig cfg;
    cfg.workspace_id = "ws_deact";
    cfg.product_id = "prod_deact";
    cfg.public_keys["kid_1"] = TEST_PUB_KEY;
    cfg.app_version = "1.0.0";
    cfg.storage_dir = "test_deact_cpp_temp";

    seatling::SeatlingClient client(cfg);
    client.initialize();

    bool deact_ok = client.deactivate();
    if (!deact_ok) {
        throw std::runtime_error("client.deactivate() returned false");
    }

    if (client.is_authorized()) {
        throw std::runtime_error("Client must not be authorized after deactivate");
    }

    if (client.status() != seatling::StatusCode::NotActivated) {
        throw std::runtime_error("Expected NotActivated after deactivate");
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << " Seatling C++ SDK Test Suite (Rust Core)" << std::endl;
    std::cout << "========================================" << std::endl;

    RUN_TEST(test_hwid);
    RUN_TEST(test_client_lifecycle_not_activated);
    RUN_TEST(test_lock_free_cache_latency_benchmark);
    RUN_TEST(test_entitlements_fallback);
    RUN_TEST(test_v3_dual_query);
    RUN_TEST(test_v6_rejection_on_empty_keys);
    RUN_TEST(test_v6_spec_syntax);
    RUN_TEST(test_v6_weighted_hwid_score);
    RUN_TEST(test_v7_base64url_public_key);
    RUN_TEST(test_client_invalid_semver_rejection);
    RUN_TEST(test_client_tampered_lease_rejection);
    RUN_TEST(test_client_deactivate);

    std::cout << "----------------------------------------" << std::endl;
    std::cout << "Results: " << (g_test_count - g_fail_count) << "/" << g_test_count << " passed." << std::endl;

    return g_fail_count == 0 ? 0 : 1;
}
