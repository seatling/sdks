#pragma once

#include "seatling.h"
#include <string>
#include <optional>
#include <memory>
#include <utility>
#include <stdexcept>
#include <vector>
#include <unordered_map>

namespace seatling {

enum class StatusCode : int32_t {
    Ok = SEATLING_STATUS_OK,
    Valid = SEATLING_STATUS_OK, // V5 alias
    OfflineGraceValid = SEATLING_STATUS_OFFLINE_GRACE_VALID,
    NotActivated = SEATLING_STATUS_NOT_ACTIVATED,
    OfflineGraceExpired = SEATLING_STATUS_OFFLINE_GRACE_EXPIRED,
    GraceExpired = SEATLING_STATUS_OFFLINE_GRACE_EXPIRED, // V5 alias (§7.4.3)
    SeatsExhausted = SEATLING_STATUS_SEATS_EXHAUSTED,
    RequiresPortalDeactivation = SEATLING_STATUS_REQUIRES_PORTAL_DEACTIVATION,
    LicenseSuspendedOrRevoked = SEATLING_STATUS_LICENSE_SUSPENDED_OR_REVOKED,
    VersionCeilingExceeded = SEATLING_STATUS_VERSION_CEILING_EXCEEDED,
    TamperOrSignatureInvalid = SEATLING_STATUS_TAMPER_OR_SIGNATURE_INVALID,
    NetworkError = SEATLING_STATUS_NETWORK_ERROR,
    TimeTamperDetected = SEATLING_STATUS_TIME_TAMPER_DETECTED,
    InvalidProductOrWorkspace = SEATLING_STATUS_INVALID_PRODUCT_OR_WORKSPACE,
    KeyRevokedUpdateRequired = SEATLING_STATUS_KEY_REVOKED_UPDATE_REQUIRED,
    InvalidConfiguration = SEATLING_STATUS_INVALID_CONFIGURATION
};

using SeatlingStatus = StatusCode;

inline const char* status_to_string(StatusCode status) noexcept {
    switch (status) {
        case StatusCode::Ok: return "OK";
        case StatusCode::OfflineGraceValid: return "OFFLINE_GRACE_VALID";
        case StatusCode::NotActivated: return "NOT_ACTIVATED";
        case StatusCode::OfflineGraceExpired: return "OFFLINE_GRACE_EXPIRED";
        case StatusCode::SeatsExhausted: return "SEATS_EXHAUSTED";
        case StatusCode::RequiresPortalDeactivation: return "REQUIRES_PORTAL_DEACTIVATION";
        case StatusCode::LicenseSuspendedOrRevoked: return "LICENSE_SUSPENDED_OR_REVOKED";
        case StatusCode::VersionCeilingExceeded: return "VERSION_CEILING_EXCEEDED";
        case StatusCode::TamperOrSignatureInvalid: return "TAMPER_OR_SIGNATURE_INVALID";
        case StatusCode::NetworkError: return "NETWORK_ERROR";
        case StatusCode::TimeTamperDetected: return "TIME_TAMPER_DETECTED";
        case StatusCode::InvalidProductOrWorkspace: return "INVALID_PRODUCT_OR_WORKSPACE";
        case StatusCode::KeyRevokedUpdateRequired: return "KEY_REVOKED_UPDATE_REQUIRED";
        case StatusCode::InvalidConfiguration: return "INVALID_CONFIGURATION";
        default: return "UNKNOWN";
    }
}

struct SeatlingConfig {
    std::string workspace_id;
    std::string product_id;
    std::unordered_map<std::string, std::string> public_keys; // map of kid -> base64 pubkey (V6 dedicated workspace key pinning)
    std::string app_version = "1.0.0";
    std::string api_base_url = "https://api.seatling.com";
    uint32_t heartbeat_interval_seconds = 14400;
    std::optional<std::string> storage_dir = std::nullopt;
};

class SeatlingClient {
public:
    using Config = SeatlingConfig;
    using Status = StatusCode;

    explicit SeatlingClient(const SeatlingConfig& config) {
        if (has_nul(config.workspace_id) || has_nul(config.product_id) ||
            has_nul(config.app_version) || has_nul(config.api_base_url) ||
            (config.storage_dir.has_value() && has_nul(*config.storage_dir))) {
            throw std::runtime_error("Configuration strings must not contain embedded NUL bytes");
        }

        seatling_config_t c_cfg{};
        c_cfg.workspace_id = config.workspace_id.c_str();
        c_cfg.product_id = config.product_id.c_str();

        std::vector<seatling_key_entry_t> key_entries;
        key_entries.reserve(config.public_keys.size());
        for (const auto& [kid, key_b64] : config.public_keys) {
            if (has_nul(kid) || has_nul(key_b64)) {
                throw std::runtime_error("Public key entries must not contain embedded NUL bytes");
            }
            seatling_key_entry_t entry;
            entry.kid = kid.c_str();
            entry.public_key_b64 = key_b64.c_str();
            key_entries.push_back(entry);
        }
        c_cfg.public_keys = key_entries.empty() ? nullptr : key_entries.data();
        c_cfg.public_keys_count = key_entries.size();

        c_cfg.app_version = config.app_version.c_str();
        c_cfg.api_base_url = config.api_base_url.c_str();
        c_cfg.heartbeat_interval_seconds = config.heartbeat_interval_seconds;
        c_cfg.storage_dir = config.storage_dir.has_value() ? config.storage_dir->c_str() : nullptr;

        m_handle = ::seatling_client_new(&c_cfg);
        if (!m_handle) {
            throw std::runtime_error("Failed to initialize Seatling Rust core client (invalid configuration or keys)");
        }
    }

    /// Factory method conforming to HARDWARE_ANCHOR_V5.md §7.1.1 (Seatling::init)
    static SeatlingClient init(const SeatlingConfig& config) {
        SeatlingClient client(config);
        client.initialize();
        return client;
    }

    ~SeatlingClient() {
        if (m_handle) {
            ::seatling_client_free(m_handle);
            m_handle = nullptr;
        }
    }

    // Non-copyable, movable
    SeatlingClient(const SeatlingClient&) = delete;
    SeatlingClient& operator=(const SeatlingClient&) = delete;

    SeatlingClient(SeatlingClient&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }

    SeatlingClient& operator=(SeatlingClient&& other) noexcept {
        if (this != &other) {
            if (m_handle) {
                ::seatling_client_free(m_handle);
            }
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }

    StatusCode initialize() {
        if (!m_handle) return StatusCode::NotActivated;
        return static_cast<StatusCode>(::seatling_client_initialize(m_handle));
    }

    bool is_authorized() const noexcept {
        if (!m_handle) return false;
        return ::seatling_client_is_authorized(m_handle);
    }

    bool is_valid() const noexcept {
        if (!m_handle) return false;
        return ::seatling_client_is_valid(m_handle);
    }

    StatusCode status() const noexcept {
        if (!m_handle) return StatusCode::NotActivated;
        return static_cast<StatusCode>(::seatling_client_status(m_handle));
    }

    bool is_valid_blocking(uint32_t timeout_ms = 8000) noexcept {
        if (!m_handle) return false;
        return ::seatling_client_is_valid_blocking(m_handle, timeout_ms);
    }

    StatusCode status_blocking(uint32_t timeout_ms = 8000) noexcept {
        if (!m_handle) return StatusCode::NotActivated;
        return static_cast<StatusCode>(::seatling_client_status_blocking(m_handle, timeout_ms));
    }

    std::string get_session_id() const {
        if (!m_handle) return "";
        char buffer[128] = {0};
        size_t len = ::seatling_client_get_session_id(m_handle, buffer, sizeof(buffer));
        return std::string(buffer, len);
    }

    bool get_entitlement_bool(const std::string& key, bool default_val = false) const noexcept {
        if (!m_handle || has_nul(key)) return default_val;
        return ::seatling_client_get_entitlement_bool(m_handle, key.c_str(), default_val);
    }

    int64_t get_entitlement_i64(const std::string& key, int64_t default_val = 0) const noexcept {
        if (!m_handle || has_nul(key)) return default_val;
        return ::seatling_client_get_entitlement_i64(m_handle, key.c_str(), default_val);
    }

    double get_entitlement_f64(const std::string& key, double default_val = 0.0) const noexcept {
        if (!m_handle || has_nul(key)) return default_val;
        return ::seatling_client_get_entitlement_f64(m_handle, key.c_str(), default_val);
    }

    bool activate(const std::string& license_key) {
        if (!m_handle || has_nul(license_key)) return false;
        return ::seatling_client_activate(m_handle, license_key.c_str());
    }

    StatusCode heartbeat_now() {
        if (!m_handle) return StatusCode::NotActivated;
        return static_cast<StatusCode>(::seatling_client_heartbeat_now(m_handle));
    }

    bool deactivate() {
        if (!m_handle) return false;
        return ::seatling_client_deactivate(m_handle);
    }

    static std::string get_hwid() {
        char buffer[128] = {0};
        size_t len = ::seatling_hwid_get(buffer, sizeof(buffer));
        return std::string(buffer, len);
    }

private:
    static bool has_nul(const std::string& s) noexcept {
        return s.find('\0') != std::string::npos;
    }

    ::SeatlingClient* m_handle{nullptr};
};

using Seatling = SeatlingClient;
using Config = SeatlingConfig;

} // namespace seatling

// Global aliases conforming directly to HARDWARE_ANCHOR_V5.md snippets
using Seatling = seatling::SeatlingClient;
using SeatlingStatus = seatling::StatusCode;
using SeatlingConfig = seatling::SeatlingConfig;
