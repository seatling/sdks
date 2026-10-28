package seatling

/*
#include "seatling.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// ErrClientClosed is returned when an operation is invoked on a closed Client.
var ErrClientClosed = errors.New("seatling: client is closed")

const maxPublicKeys = 64

// Client wraps the native Seatling Rust core client engine via direct CGO static linking.
// It is fully thread-safe and safe for concurrent use across multiple goroutines.
type Client struct {
	rawClient *C.SeatlingClient
	// state bit 0: closed flag; bits 1..63: active in-flight FFI call count.
	state   atomic.Uint64
	drainCh chan struct{}
	closeMu sync.Mutex
}

func hasNul(s string) bool {
	return strings.IndexByte(s, 0) >= 0
}

func validateAPIBaseURL(raw string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	if trimmed == "" ||
		strings.ContainsAny(trimmed, "?#@\\ \t\r\n") ||
		strings.Contains(trimmed, "..") {
		return "", errors.New("seatling: invalid api_base_url")
	}

	var rest string
	if after, ok := strings.CutPrefix(trimmed, "https://"); ok {
		rest = after
	} else if after, ok := strings.CutPrefix(trimmed, "http://"); ok {
		host := strings.SplitN(after, "/", 2)[0]
		isLoopback := host == "127.0.0.1" ||
			strings.HasPrefix(host, "127.0.0.1:") ||
			host == "localhost" ||
			strings.HasPrefix(host, "localhost:") ||
			host == "[::1]" ||
			strings.HasPrefix(host, "[::1]:")
		if !isLoopback {
			return "", errors.New("seatling: cleartext http:// api_base_url is only permitted for loopback addresses")
		}
		rest = after
	} else {
		return "", errors.New("seatling: api_base_url must use https:// scheme")
	}

	host := strings.SplitN(rest, "/", 2)[0]
	if host == "" || strings.HasPrefix(host, ":") {
		return "", errors.New("seatling: api_base_url is missing host")
	}
	return trimmed, nil
}

func clampTimeoutMs(timeout time.Duration) C.uint32_t {
	ms := timeout.Milliseconds()
	if ms <= 0 {
		return 1
	}
	if ms > math.MaxUint32 {
		return C.uint32_t(math.MaxUint32)
	}
	return C.uint32_t(ms)
}

func (c *Client) acquire() (*C.SeatlingClient, bool) {
	for {
		cur := c.state.Load()
		if cur&1 != 0 {
			return nil, false
		}
		if c.state.CompareAndSwap(cur, cur+2) {
			return c.rawClient, true
		}
	}
}

func (c *Client) release() {
	if c.state.Add(^uint64(1)) == 1 {
		close(c.drainCh)
	}
	runtime.KeepAlive(c)
}

func validateIdentifier(id, fieldName string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" || len(trimmed) > 128 {
		return errors.New("seatling: " + fieldName + " must be 1-128 characters")
	}
	hasAlphanumeric := false
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			hasAlphanumeric = true
			break
		}
	}
	if !hasAlphanumeric {
		return errors.New("seatling: " + fieldName + " must contain at least one alphanumeric character")
	}
	return nil
}

// New creates and configures a new SeatlingClient instance.
func New(cfg Config) (*Client, error) {
	if err := validateIdentifier(cfg.WorkspaceID, "workspace_id"); err != nil {
		return nil, err
	}
	if err := validateIdentifier(cfg.ProductID, "product_id"); err != nil {
		return nil, err
	}
	if len(cfg.PublicKeys) == 0 {
		return nil, errors.New("seatling: public_keys must contain at least one authoritative signing key (kid -> base64/base64url)")
	}
	if len(cfg.PublicKeys) > maxPublicKeys {
		return nil, errors.New("seatling: public_keys exceeds maximum allowed key count (64)")
	}
	if hasNul(cfg.WorkspaceID) || hasNul(cfg.ProductID) || hasNul(cfg.AppVersion) || hasNul(cfg.APIBaseURL) || hasNul(cfg.StorageDir) {
		return nil, errors.New("seatling: configuration strings must not contain NUL bytes")
	}
	for kid, keyB64 := range cfg.PublicKeys {
		if kid == "" || keyB64 == "" {
			return nil, errors.New("seatling: public_keys entries must not have empty kid or key")
		}
		if hasNul(kid) || hasNul(keyB64) {
			return nil, errors.New("seatling: public_keys entries must not contain NUL bytes")
		}
	}

	cWorkspaceID := C.CString(cfg.WorkspaceID)
	defer C.free(unsafe.Pointer(cWorkspaceID))

	cProductID := C.CString(cfg.ProductID)
	defer C.free(unsafe.Pointer(cProductID))

	appVerStr := cfg.AppVersion
	if appVerStr == "" {
		appVerStr = "1.0.0"
	}
	cAppVersion := C.CString(appVerStr)
	defer C.free(unsafe.Pointer(cAppVersion))

	apiURLStr := cfg.APIBaseURL
	if apiURLStr == "" {
		apiURLStr = "https://api.seatling.com"
	}
	validatedURL, err := validateAPIBaseURL(apiURLStr)
	if err != nil {
		return nil, err
	}
	cAPIBaseURL := C.CString(validatedURL)
	defer C.free(unsafe.Pointer(cAPIBaseURL))

	var cStorageDir *C.char
	if cfg.StorageDir != "" {
		cStorageDir = C.CString(cfg.StorageDir)
		defer C.free(unsafe.Pointer(cStorageDir))
	}

	// Marshaling public key entries using C.malloc to satisfy CGO pointer rules
	entryCount := len(cfg.PublicKeys)
	entrySize := C.size_t(unsafe.Sizeof(C.seatling_key_entry_t{}))
	entriesMem := C.malloc(C.size_t(entryCount) * entrySize)
	if entriesMem == nil {
		return nil, errors.New("seatling: failed to allocate C memory for public_keys")
	}
	defer C.free(entriesMem)

	cKeyEntries := unsafe.Slice((*C.seatling_key_entry_t)(entriesMem), entryCount)
	cAllocatedStrings := make([]*C.char, 0, entryCount*2)
	defer func() {
		for _, ptr := range cAllocatedStrings {
			C.free(unsafe.Pointer(ptr))
		}
	}()

	idx := 0
	for kid, keyB64 := range cfg.PublicKeys {
		cKID := C.CString(kid)
		cKeyB64 := C.CString(keyB64)
		cAllocatedStrings = append(cAllocatedStrings, cKID, cKeyB64)
		cKeyEntries[idx] = C.seatling_key_entry_t{
			kid:            cKID,
			public_key_b64: cKeyB64,
		}
		idx++
	}

	var cKeyEntriesPtr *C.seatling_key_entry_t
	if entryCount > 0 {
		cKeyEntriesPtr = (*C.seatling_key_entry_t)(entriesMem)
	}

	cConfig := C.seatling_config_t{
		workspace_id:               cWorkspaceID,
		product_id:                 cProductID,
		public_keys:                cKeyEntriesPtr,
		public_keys_count:          C.size_t(len(cKeyEntries)),
		app_version:                cAppVersion,
		api_base_url:               cAPIBaseURL,
		heartbeat_interval_seconds: C.uint32_t(cfg.HeartbeatIntervalSeconds),
		storage_dir:                cStorageDir,
	}

	rawPtr := C.seatling_client_new(&cConfig)
	if rawPtr == nil {
		return nil, errors.New("seatling: failed to construct native SeatlingClient (invalid configuration or keys)")
	}

	c := &Client{
		rawClient: rawPtr,
		drainCh:   make(chan struct{}),
	}

	runtime.SetFinalizer(c, func(client *Client) {
		go func() {
			_ = client.Close()
		}()
	})

	return c, nil
}

// Initialize performs non-blocking offline cache verification (< 1ms, zero network I/O).
// Safe to call immediately during application startup.
func (c *Client) Initialize() (StatusCode, error) {
	ptr, ok := c.acquire()
	if !ok {
		return StatusNotActivated, ErrClientClosed
	}
	defer c.release()
	status := StatusCode(C.seatling_client_initialize(ptr))
	return status, nil
}

// IsAuthorized verifies whether the active lease is authorized (active or offline grace).
// Hot-path lock-free atomic read (~40ns, 0 heap allocations). Ideal for render loops and middleware checks.
func (c *Client) IsAuthorized() bool {
	ptr, ok := c.acquire()
	if !ok {
		return false
	}
	res := bool(C.seatling_client_is_authorized(ptr))
	c.release()
	return res
}

// IsValid checks if the current license lease is valid (active OK or within offline grace).
func (c *Client) IsValid() bool {
	ptr, ok := c.acquire()
	if !ok {
		return false
	}
	res := bool(C.seatling_client_is_valid(ptr))
	c.release()
	return res
}

// Status returns the current detailed StatusCode.
func (c *Client) Status() StatusCode {
	ptr, ok := c.acquire()
	if !ok {
		return StatusNotActivated
	}
	status := StatusCode(C.seatling_client_status(ptr))
	c.release()
	return status
}

// IsValidBlocking blocks until background network verification completes or timeout elapses.
func (c *Client) IsValidBlocking(timeout time.Duration) bool {
	ptr, ok := c.acquire()
	if !ok {
		return false
	}
	defer c.release()
	timeoutMs := clampTimeoutMs(timeout)
	return bool(C.seatling_client_is_valid_blocking(ptr, timeoutMs))
}

// StatusBlocking blocks until background network verification completes or timeout elapses.
func (c *Client) StatusBlocking(timeout time.Duration) (StatusCode, error) {
	ptr, ok := c.acquire()
	if !ok {
		return StatusNotActivated, ErrClientClosed
	}
	defer c.release()
	timeoutMs := clampTimeoutMs(timeout)
	status := StatusCode(C.seatling_client_status_blocking(ptr, timeoutMs))
	return status, nil
}

// SessionID returns the ephemeral cryptographic session ID generated for this client instance.
func (c *Client) SessionID() string {
	ptr, ok := c.acquire()
	if !ok {
		return ""
	}
	defer c.release()
	buf := make([]byte, 128)
	copied := C.seatling_client_get_session_id(ptr, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if copied == 0 || int(copied) > len(buf) {
		return ""
	}
	return string(buf[:copied])
}

// GetEntitlementBool queries a boolean entitlement flag from the active lease snapshot.
func (c *Client) GetEntitlementBool(key string, defaultValue bool) bool {
	if hasNul(key) {
		return defaultValue
	}
	ptr, ok := c.acquire()
	if !ok {
		return defaultValue
	}
	defer c.release()
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))
	return bool(C.seatling_client_get_entitlement_bool(ptr, cKey, C.bool(defaultValue)))
}

// GetEntitlementInt64 queries an integer entitlement limit from the active lease snapshot.
func (c *Client) GetEntitlementInt64(key string, defaultValue int64) int64 {
	if hasNul(key) {
		return defaultValue
	}
	ptr, ok := c.acquire()
	if !ok {
		return defaultValue
	}
	defer c.release()
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))
	return int64(C.seatling_client_get_entitlement_i64(ptr, cKey, C.int64_t(defaultValue)))
}

// GetEntitlementFloat64 queries a floating-point entitlement limit from the active lease snapshot.
func (c *Client) GetEntitlementFloat64(key string, defaultValue float64) float64 {
	if hasNul(key) {
		return defaultValue
	}
	ptr, ok := c.acquire()
	if !ok {
		return defaultValue
	}
	defer c.release()
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))
	return float64(C.seatling_client_get_entitlement_f64(ptr, cKey, C.double(defaultValue)))
}

// Activate performs an online activation with the Seatling licensing service using a license key.
func (c *Client) Activate(licenseKey string) (bool, error) {
	if hasNul(licenseKey) {
		return false, errors.New("seatling: license_key must not contain NUL bytes")
	}
	ptr, ok := c.acquire()
	if !ok {
		return false, ErrClientClosed
	}
	defer c.release()
	cLicenseKey := C.CString(licenseKey)
	defer C.free(unsafe.Pointer(cLicenseKey))
	return bool(C.seatling_client_activate(ptr, cLicenseKey)), nil
}

// ActivateDetailed performs an online activation returning rich server diagnostics, status codes, and portal URLs.
func (c *Client) ActivateDetailed(licenseKey string) (ActivationResult, error) {
	if hasNul(licenseKey) {
		return ActivationResult{
			Success: false,
			Status:  StatusInvalidConfiguration,
			Message: "seatling: license_key must not contain NUL bytes",
		}, errors.New("seatling: license_key must not contain NUL bytes")
	}
	ptr, ok := c.acquire()
	if !ok {
		return ActivationResult{
			Success: false,
			Status:  StatusNotActivated,
			Message: "seatling: client is closed",
		}, ErrClientClosed
	}
	defer c.release()

	cLicenseKey := C.CString(licenseKey)
	defer C.free(unsafe.Pointer(cLicenseKey))

	var cResult C.seatling_activation_result_t
	C.seatling_client_activate_detailed(ptr, cLicenseKey, &cResult)
	defer C.seatling_activation_result_free(&cResult)

	res := ActivationResult{
		Success:     bool(cResult.success),
		Status:      StatusCode(cResult.status),
		SeatsActive: int32(cResult.seats_active),
		SeatLimit:   int32(cResult.seat_limit),
	}
	if cResult.message != nil {
		res.Message = C.GoString(cResult.message)
	}
	if cResult.seat_id != nil {
		res.SeatID = C.GoString(cResult.seat_id)
	}
	if cResult.portal_url != nil {
		res.PortalURL = C.GoString(cResult.portal_url)
	}
	if cResult.buyer_email != nil {
		res.BuyerEmail = C.GoString(cResult.buyer_email)
	}

	return res, nil
}

// HeartbeatNow manually triggers an immediate background heartbeat refresh.
func (c *Client) HeartbeatNow() (StatusCode, error) {
	ptr, ok := c.acquire()
	if !ok {
		return StatusNotActivated, ErrClientClosed
	}
	defer c.release()
	status := StatusCode(C.seatling_client_heartbeat_now(ptr))
	return status, nil
}

// Deactivate releases the seat allocation associated with this client instance on the server.
// If the server is unreachable, it defaults to forcing local lease teardown.
func (c *Client) Deactivate() (bool, error) {
	return c.DeactivateWithTimeout(8*time.Second, true)
}

// DeactivateWithTimeout releases the seat allocation with an explicit network timeout and force policy.
func (c *Client) DeactivateWithTimeout(timeout time.Duration, force bool) (bool, error) {
	ptr, ok := c.acquire()
	if !ok {
		return false, ErrClientClosed
	}
	defer c.release()
	timeoutMs := clampTimeoutMs(timeout)
	return bool(C.seatling_client_deactivate_detailed(ptr, timeoutMs, C.bool(force))), nil
}

// Close frees native memory and halts any active background workers.
func (c *Client) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()

	var prev uint64
	for {
		prev = c.state.Load()
		if prev&1 != 0 {
			return nil
		}
		if c.state.CompareAndSwap(prev, prev|1) {
			break
		}
	}

	// Wait for any in-flight FFI calls to finish before freeing rawClient
	if prev>>1 != 0 {
		<-c.drainCh
	}

	if c.rawClient != nil {
		C.seatling_client_free(c.rawClient)
		c.rawClient = nil
	}
	runtime.SetFinalizer(c, nil)
	return nil
}
