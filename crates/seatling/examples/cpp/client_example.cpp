// =============================================================================
// Example Generic C++ Application Integration with Seatling Client SDK
// Conforms to: SDK_ARCHITECTURE.md & HARDWARE_ANCHOR.md
// Targets: Any C++17 Application (Desktop GUI, CLI Tools, Games, Native Services)
// =============================================================================

#include <iostream>
#include <string>
#include "seatling/seatling.hpp"

// Example application configuration per HARDWARE_ANCHOR_V7.md §7.1.1
seatling::SeatlingConfig create_seatling_config() {
    seatling::SeatlingConfig cfg;
    cfg.workspace_id = "ws_creator_demo";
    cfg.product_id = "prod_creative_suite";
    // Authoritative kid and Base64URL-encoded public key from Creator Dashboard
    cfg.public_keys["ws_creator_demo_2026_v1"] = "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";
    cfg.app_version = "1.0.0";
    cfg.heartbeat_interval_seconds = 14400; // 4 hours
    return cfg;
}

class Application {
public:
    Application()
        : m_client(create_seatling_config()) {}

    void startup() {
        std::cout << "[App] Starting application..." << std::endl;

        // 1. Synchronous startup check (< 1ms, zero network I/O)
        auto status = m_client.initialize();
        std::cout << "[App] License status: " << seatling::status_to_string(status) << std::endl;

        // 2. Developer-defined verification policy:
        // Developers decide what policy to enforce if the license cannot be verified.
        if (!m_client.is_authorized()) {
            handle_unauthorized_state(status);
        } else {
            std::cout << "[App] Welcome! Running with active authorized seat." << std::endl;
        }
    }

    void run_feature() {
        // 3. Fast hot-path check (< 0.01ms, lock-free, safe in 120fps loops and worker threads)
        if (!m_client.is_authorized()) {
            std::cout << "[Feature] Feature unavailable: license is not authorized." << std::endl;
            return;
        }

        // 4. Access signed runtime entitlements
        int64_t max_resolution = m_client.get_entitlement_i64("max_export_resolution", 1080);
        bool pro_features = m_client.get_entitlement_bool("pro_enabled", false);
        double multiplier = m_client.get_entitlement_f64("speed_multiplier", 1.0);

        std::cout << "[Feature] Executing feature with:" << std::endl;
        std::cout << "  - Max resolution: " << max_resolution << "p" << std::endl;
        std::cout << "  - Pro features enabled: " << (pro_features ? "yes" : "no") << std::endl;
        std::cout << "  - Speed multiplier: " << multiplier << "x" << std::endl;
    }

    void activate_license(const std::string& key) {
        std::cout << "[App] Activating key: " << key << " ..." << std::endl;
        bool ok = m_client.activate(key);
        if (ok) {
            std::cout << "[Callback] License activated successfully!" << std::endl;
        } else {
            std::cout << "[Callback] Activation failed." << std::endl;
        }
    }

    void deactivate_license() {
        std::cout << "[App] Deactivating license..." << std::endl;
        bool ok = m_client.deactivate();
        if (ok) {
            std::cout << "[Callback] Seat released and deactivated successfully." << std::endl;
        } else {
            std::cout << "[Callback] Deactivation failed." << std::endl;
        }
    }

private:
    void handle_unauthorized_state(seatling::StatusCode status) {
        switch (status) {
            case seatling::StatusCode::NotActivated:
                std::cout << "[Policy] Application is not activated. Prompting user for license key..." << std::endl;
                break;
            case seatling::StatusCode::OfflineGraceExpired:
                std::cout << "[Policy] Offline grace period expired. Reconnect to internet to continue." << std::endl;
                break;
            case seatling::StatusCode::LicenseSuspendedOrRevoked:
                std::cout << "[Policy] License has been suspended or revoked. Exiting feature mode." << std::endl;
                break;
            case seatling::StatusCode::TamperOrSignatureInvalid:
                std::cout << "[Policy] Tamper detected or invalid signature. Exiting." << std::endl;
                break;
            default:
                std::cout << "[Policy] Running in restricted demo / evaluation mode." << std::endl;
                break;
        }
    }

    seatling::SeatlingClient m_client;
};

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << " Seatling C++ Generic Client Example    " << std::endl;
    std::cout << "========================================" << std::endl;

    Application app;
    app.startup();
    app.run_feature();

    std::cout << "Example executed successfully." << std::endl;
    return 0;
}
