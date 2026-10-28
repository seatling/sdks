#![allow(clippy::missing_safety_doc)]

use crate::client::SeatlingClient;
use crate::types::{SeatlingConfig, StatusCode};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[repr(C)]
pub struct seatling_key_entry_t {
    pub kid: *const c_char,
    pub public_key_b64: *const c_char,
}

#[repr(C)]
pub struct seatling_config_t {
    pub workspace_id: *const c_char,
    pub product_id: *const c_char,
    pub public_keys: *const seatling_key_entry_t,
    pub public_keys_count: usize,
    pub app_version: *const c_char,
    pub api_base_url: *const c_char,
    pub heartbeat_interval_seconds: u32,
    pub storage_dir: *const c_char,
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_new(
    config: *const seatling_config_t,
) -> *mut SeatlingClient {
    catch_unwind(AssertUnwindSafe(|| {
        if config.is_null() {
            return std::ptr::null_mut();
        }

        // SAFETY: Caller guarantees `config` points to a valid `seatling_config_t`.
        let cfg = unsafe { &*config };
        let ws_id = match unsafe { c_str_to_string(cfg.workspace_id) } {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let prod_id = match unsafe { c_str_to_string(cfg.product_id) } {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        const MAX_PUBLIC_KEYS: usize = 64;
        let ws_keys = if !cfg.public_keys.is_null()
            && cfg.public_keys_count > 0
            && cfg.public_keys_count <= MAX_PUBLIC_KEYS
        {
            let mut map = std::collections::HashMap::new();
            // SAFETY: `cfg.public_keys` is non-null and within `isize::MAX` byte bounds.
            let entries =
                unsafe { std::slice::from_raw_parts(cfg.public_keys, cfg.public_keys_count) };
            for entry in entries {
                let (Some(kid), Some(key)) = (unsafe {
                    (
                        c_str_to_string(entry.kid),
                        c_str_to_string(entry.public_key_b64),
                    )
                }) else {
                    return std::ptr::null_mut();
                };
                if kid.is_empty() || key.is_empty() || map.insert(kid, key).is_some() {
                    return std::ptr::null_mut();
                }
            }
            map
        } else {
            return std::ptr::null_mut();
        };
        let app_ver =
            unsafe { c_str_to_string(cfg.app_version) }.unwrap_or_else(|| "1.0.0".to_string());
        let api_url = unsafe { c_str_to_string(cfg.api_base_url) }
            .unwrap_or_else(|| "https://api.seatling.com".to_string());
        let storage_dir = unsafe { c_str_to_string(cfg.storage_dir) };
        let interval = if cfg.heartbeat_interval_seconds == 0 {
            14400
        } else {
            cfg.heartbeat_interval_seconds
        };

        let rust_config = SeatlingConfig {
            workspace_id: ws_id,
            product_id: prod_id,
            public_keys: ws_keys,
            app_version: app_ver,
            api_base_url: api_url,
            heartbeat_interval_seconds: interval,
            storage_dir,
        };

        match SeatlingClient::new(rust_config) {
            Ok(client) => Box::into_raw(Box::new(client)),
            Err(_) => std::ptr::null_mut(),
        }
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_initialize(client: *mut SeatlingClient) -> StatusCode {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() {
            return StatusCode::NotActivated;
        }
        // SAFETY: Caller guarantees `client` is a valid pointer returned by `seatling_client_new`.
        let c = unsafe { &*client };
        c.initialize().status
    }))
    .unwrap_or(StatusCode::TamperOrSignatureInvalid)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_is_authorized(client: *const SeatlingClient) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() {
            return false;
        }
        // SAFETY: Caller guarantees `client` is a valid pointer returned by `seatling_client_new`.
        let c = unsafe { &*client };
        c.is_authorized()
    }))
    .unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_is_valid(client: *const SeatlingClient) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() {
            return false;
        }
        // SAFETY: Caller guarantees `client` is a valid pointer returned by `seatling_client_new`.
        let c = unsafe { &*client };
        c.is_valid()
    }))
    .unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_status(client: *const SeatlingClient) -> StatusCode {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() {
            return StatusCode::NotActivated;
        }
        // SAFETY: Caller guarantees `client` is a valid pointer returned by `seatling_client_new`.
        let c = unsafe { &*client };
        c.status()
    }))
    .unwrap_or(StatusCode::TamperOrSignatureInvalid)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_is_valid_blocking(
    client: *mut SeatlingClient,
    timeout_ms: u32,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() {
            return false;
        }
        // SAFETY: Caller guarantees `client` is a valid pointer returned by `seatling_client_new`.
        let c = unsafe { &*client };
        let timeout = if timeout_ms == 0 {
            std::time::Duration::from_secs(8)
        } else {
            std::time::Duration::from_millis(timeout_ms as u64)
        };
        c.is_valid_blocking(timeout)
    }))
    .unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_status_blocking(
    client: *mut SeatlingClient,
    timeout_ms: u32,
) -> StatusCode {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() {
            return StatusCode::NotActivated;
        }
        // SAFETY: Caller guarantees `client` is a valid pointer returned by `seatling_client_new`.
        let c = unsafe { &*client };
        let timeout = if timeout_ms == 0 {
            std::time::Duration::from_secs(8)
        } else {
            std::time::Duration::from_millis(timeout_ms as u64)
        };
        c.status_blocking(timeout).status
    }))
    .unwrap_or(StatusCode::TamperOrSignatureInvalid)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_is_valid(client: *const SeatlingClient) -> bool {
    unsafe { seatling_client_is_valid(client) }
}

#[no_mangle]
pub unsafe extern "C" fn seatling_status(client: *const SeatlingClient) -> StatusCode {
    unsafe { seatling_client_status(client) }
}

#[no_mangle]
pub unsafe extern "C" fn seatling_is_valid_blocking(
    client: *mut SeatlingClient,
    timeout_ms: u32,
) -> bool {
    unsafe { seatling_client_is_valid_blocking(client, timeout_ms) }
}

#[no_mangle]
pub unsafe extern "C" fn seatling_status_blocking(
    client: *mut SeatlingClient,
    timeout_ms: u32,
) -> StatusCode {
    unsafe { seatling_client_status_blocking(client, timeout_ms) }
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_get_session_id(
    client: *const SeatlingClient,
    buffer: *mut c_char,
    buffer_len: usize,
) -> usize {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() || buffer.is_null() || buffer_len == 0 {
            return 0;
        }
        // SAFETY: Caller guarantees `client` and `buffer` (of length `buffer_len`) are valid.
        let c = unsafe { &*client };
        let session_id = c.session_id();
        let bytes = session_id.as_bytes();
        let copy_len = bytes.len().min(buffer_len.saturating_sub(1));
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buffer, copy_len);
            *buffer.add(copy_len) = 0;
        }
        copy_len
    }))
    .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_get_entitlement_bool(
    client: *const SeatlingClient,
    key: *const c_char,
    default_value: bool,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() || key.is_null() {
            return default_value;
        }
        // SAFETY: Caller guarantees `client` and `key` are valid pointers.
        let c = unsafe { &*client };
        if let Some(k) = unsafe { c_str_to_string(key) } {
            c.get_entitlement_bool(&k, default_value)
        } else {
            default_value
        }
    }))
    .unwrap_or(default_value)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_get_entitlement_i64(
    client: *const SeatlingClient,
    key: *const c_char,
    default_value: i64,
) -> i64 {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() || key.is_null() {
            return default_value;
        }
        // SAFETY: Caller guarantees `client` and `key` are valid pointers.
        let c = unsafe { &*client };
        if let Some(k) = unsafe { c_str_to_string(key) } {
            c.get_entitlement_i64(&k, default_value)
        } else {
            default_value
        }
    }))
    .unwrap_or(default_value)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_get_entitlement_f64(
    client: *const SeatlingClient,
    key: *const c_char,
    default_value: f64,
) -> f64 {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() || key.is_null() {
            return default_value;
        }
        // SAFETY: Caller guarantees `client` and `key` are valid pointers.
        let c = unsafe { &*client };
        if let Some(k) = unsafe { c_str_to_string(key) } {
            c.get_entitlement_f64(&k, default_value)
        } else {
            default_value
        }
    }))
    .unwrap_or(default_value)
}

#[repr(C)]
pub struct seatling_activation_result_t {
    pub success: bool,
    pub status: StatusCode,
    pub message: *mut c_char,
    pub seat_id: *mut c_char,
    pub portal_url: *mut c_char,
    pub buyer_email: *mut c_char,
    pub seats_active: i32,
    pub seat_limit: i32,
}

fn string_to_c_char(s: Option<String>) -> *mut c_char {
    match s {
        Some(val) => CString::new(val)
            .map(|cs| cs.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

fn free_c_char(p: *mut c_char) {
    if !p.is_null() {
        unsafe {
            drop(CString::from_raw(p));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn seatling_activation_result_free(res: *mut seatling_activation_result_t) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !res.is_null() {
            let r = unsafe { &mut *res };
            free_c_char(r.message);
            r.message = std::ptr::null_mut();
            free_c_char(r.seat_id);
            r.seat_id = std::ptr::null_mut();
            free_c_char(r.portal_url);
            r.portal_url = std::ptr::null_mut();
            free_c_char(r.buyer_email);
            r.buyer_email = std::ptr::null_mut();
        }
    }));
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_activate_detailed(
    client: *mut SeatlingClient,
    license_key: *const c_char,
    out_result: *mut seatling_activation_result_t,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() || license_key.is_null() || out_result.is_null() {
            return false;
        }
        let c = unsafe { &*client };
        let out = unsafe { &mut *out_result };
        if let Some(key) = unsafe { c_str_to_string(license_key) } {
            let res = c.activate(&key);
            out.success = res.success;
            out.status = res.status;
            out.message = string_to_c_char(Some(res.message));
            out.seat_id = string_to_c_char(res.seat_id);
            out.portal_url = string_to_c_char(res.portal_url);
            out.buyer_email = string_to_c_char(res.buyer_email);
            out.seats_active = res.seats_active.unwrap_or(-1);
            out.seat_limit = res.seat_limit.unwrap_or(-1);
            res.success
        } else {
            out.success = false;
            out.status = StatusCode::InvalidConfiguration;
            out.message = string_to_c_char(Some("Invalid license key string".to_string()));
            out.seat_id = std::ptr::null_mut();
            out.portal_url = std::ptr::null_mut();
            out.buyer_email = std::ptr::null_mut();
            out.seats_active = -1;
            out.seat_limit = -1;
            false
        }
    }))
    .unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_activate(
    client: *mut SeatlingClient,
    license_key: *const c_char,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() || license_key.is_null() {
            return false;
        }
        // SAFETY: Caller guarantees `client` and `license_key` are valid pointers.
        let c = unsafe { &*client };
        if let Some(key) = unsafe { c_str_to_string(license_key) } {
            let res = c.activate(&key);
            res.success
        } else {
            false
        }
    }))
    .unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_heartbeat_now(client: *mut SeatlingClient) -> StatusCode {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() {
            return StatusCode::NotActivated;
        }
        // SAFETY: Caller guarantees `client` is a valid pointer.
        let c = unsafe { &*client };
        c.heartbeat_now().status
    }))
    .unwrap_or(StatusCode::NetworkError)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_deactivate(client: *mut SeatlingClient) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() {
            return false;
        }
        // SAFETY: Caller guarantees `client` is a valid pointer.
        let c = unsafe { &*client };
        c.deactivate().is_ok()
    }))
    .unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_deactivate_detailed(
    client: *mut SeatlingClient,
    timeout_ms: u32,
    force: bool,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() {
            return false;
        }
        // SAFETY: Caller guarantees `client` is a valid pointer.
        let c = unsafe { &*client };
        let timeout = if timeout_ms == 0 {
            std::time::Duration::from_secs(8)
        } else {
            std::time::Duration::from_millis(timeout_ms as u64)
        };
        c.deactivate_with_options(timeout, force).is_ok()
    }))
    .unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_client_free(client: *mut SeatlingClient) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !client.is_null() {
            // SAFETY: Caller guarantees `client` was allocated by `seatling_client_new` and is freed once.
            let _ = unsafe { Box::from_raw(client) };
        }
    }));
}

#[no_mangle]
pub unsafe extern "C" fn seatling_hwid_get(buffer: *mut c_char, buffer_len: usize) -> usize {
    catch_unwind(AssertUnwindSafe(|| {
        if buffer.is_null() || buffer_len == 0 {
            return 0;
        }
        let hwid = crate::hwid::HWIDCollector::get_hwid();
        let bytes = hwid.as_bytes();
        let copy_len = bytes.len().min(buffer_len.saturating_sub(1));
        // SAFETY: Caller guarantees `buffer` has at least `buffer_len` writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buffer, copy_len);
            *buffer.add(copy_len) = 0;
        }
        copy_len
    }))
    .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn seatling_hwid_weighted_score(
    base_cpu: *const c_char,
    base_mobo: *const c_char,
    base_disk: *const c_char,
    base_os: *const c_char,
    curr_cpu: *const c_char,
    curr_mobo: *const c_char,
    curr_disk: *const c_char,
    curr_os: *const c_char,
) -> u32 {
    catch_unwind(AssertUnwindSafe(|| {
        let base = crate::types::HWIDComponents {
            cpu: unsafe { c_str_to_string(base_cpu) }.unwrap_or_default(),
            mobo: unsafe { c_str_to_string(base_mobo) }.unwrap_or_default(),
            disk: unsafe { c_str_to_string(base_disk) }.unwrap_or_default(),
            os_uuid: unsafe { c_str_to_string(base_os) }.unwrap_or_default(),
        };
        let curr = crate::types::HWIDComponents {
            cpu: unsafe { c_str_to_string(curr_cpu) }.unwrap_or_default(),
            mobo: unsafe { c_str_to_string(curr_mobo) }.unwrap_or_default(),
            disk: unsafe { c_str_to_string(curr_disk) }.unwrap_or_default(),
            os_uuid: unsafe { c_str_to_string(curr_os) }.unwrap_or_default(),
        };
        crate::hwid::HWIDCollector::weighted_score(&base, &curr)
    }))
    .unwrap_or(0)
}

unsafe fn c_str_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        // SAFETY: Caller guarantees `ptr` points to a valid NUL-terminated C string.
        unsafe { CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string()) }
    }
}
