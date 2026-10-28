#ifndef SEATLING_H
#define SEATLING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum seatling_status_code_t {
    SEATLING_STATUS_OK = 0,
    SEATLING_STATUS_OFFLINE_GRACE_VALID = 1,
    SEATLING_STATUS_NOT_ACTIVATED = 2,
    SEATLING_STATUS_OFFLINE_GRACE_EXPIRED = 3,
    SEATLING_STATUS_SEATS_EXHAUSTED = 4,
    SEATLING_STATUS_REQUIRES_PORTAL_DEACTIVATION = 5,
    SEATLING_STATUS_LICENSE_SUSPENDED_OR_REVOKED = 6,
    SEATLING_STATUS_VERSION_CEILING_EXCEEDED = 7,
    SEATLING_STATUS_TAMPER_OR_SIGNATURE_INVALID = 8,
    SEATLING_STATUS_NETWORK_ERROR = 9,
    SEATLING_STATUS_TIME_TAMPER_DETECTED = 10,
    SEATLING_STATUS_INVALID_PRODUCT_OR_WORKSPACE = 11,
    SEATLING_STATUS_KEY_REVOKED_UPDATE_REQUIRED = 12,
    SEATLING_STATUS_INVALID_CONFIGURATION = 13
} seatling_status_code_t;

typedef struct seatling_key_entry_t {
    const char* kid;
    const char* public_key_b64;
} seatling_key_entry_t;

typedef struct seatling_config_t {
    const char* workspace_id;
    const char* product_id;
    const seatling_key_entry_t* public_keys;
    size_t public_keys_count;
    const char* app_version;
    const char* api_base_url;
    uint32_t heartbeat_interval_seconds;
    const char* storage_dir;
} seatling_config_t;

typedef struct SeatlingClient SeatlingClient;

SeatlingClient* seatling_client_new(const seatling_config_t* config);
seatling_status_code_t seatling_client_initialize(SeatlingClient* client);
bool seatling_client_is_authorized(const SeatlingClient* client);
bool seatling_client_is_valid(const SeatlingClient* client);
seatling_status_code_t seatling_client_status(const SeatlingClient* client);
bool seatling_client_is_valid_blocking(SeatlingClient* client, uint32_t timeout_ms);
seatling_status_code_t seatling_client_status_blocking(SeatlingClient* client, uint32_t timeout_ms);

bool seatling_is_valid(const SeatlingClient* client);
seatling_status_code_t seatling_status(const SeatlingClient* client);
bool seatling_is_valid_blocking(SeatlingClient* client, uint32_t timeout_ms);
seatling_status_code_t seatling_status_blocking(SeatlingClient* client, uint32_t timeout_ms);
size_t seatling_client_get_session_id(const SeatlingClient* client, char* buffer, size_t buffer_len);
bool seatling_client_get_entitlement_bool(const SeatlingClient* client, const char* key, bool default_value);
int64_t seatling_client_get_entitlement_i64(const SeatlingClient* client, const char* key, int64_t default_value);
double seatling_client_get_entitlement_f64(const SeatlingClient* client, const char* key, double default_value);
typedef struct seatling_activation_result_t {
    bool success;
    seatling_status_code_t status;
    const char* message;
    const char* seat_id;
    const char* portal_url;
    const char* buyer_email;
    int32_t seats_active;
    int32_t seat_limit;
} seatling_activation_result_t;

bool seatling_client_activate(SeatlingClient* client, const char* license_key);
bool seatling_client_activate_detailed(
    SeatlingClient* client,
    const char* license_key,
    seatling_activation_result_t* out_result
);
void seatling_activation_result_free(seatling_activation_result_t* result);
seatling_status_code_t seatling_client_heartbeat_now(SeatlingClient* client);
bool seatling_client_deactivate(SeatlingClient* client);
bool seatling_client_deactivate_detailed(
    SeatlingClient* client,
    uint32_t timeout_ms,
    bool force
);
void seatling_client_free(SeatlingClient* client);
size_t seatling_hwid_get(char* buffer, size_t buffer_len);
uint32_t seatling_hwid_weighted_score(
    const char* base_cpu,
    const char* base_mobo,
    const char* base_disk,
    const char* base_os,
    const char* curr_cpu,
    const char* curr_mobo,
    const char* curr_disk,
    const char* curr_os
);

#ifdef __cplusplus
}
#endif

#endif /* SEATLING_H */
