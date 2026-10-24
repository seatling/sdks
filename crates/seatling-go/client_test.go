package seatling_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/seatling/seatling-sdk-go"
)

const (
	testWorkspaceID = "ws_test_01j8k9m0n1p2q3r4s5t6u7v8w9"
	testProductID   = "prod_test_app"
	testKeyID       = "test_key_2026_v1"
	testPubKeyB64   = "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw="
)

func validTestConfig() seatling.Config {
	return seatling.Config{
		WorkspaceID: testWorkspaceID,
		ProductID:   testProductID,
		PublicKeys: map[string]string{
			testKeyID: testPubKeyB64,
		},
		AppVersion:               "1.2.3",
		APIBaseURL:               "https://api.seatling.com",
		HeartbeatIntervalSeconds: 3600,
	}
}

func TestConfigValidation(t *testing.T) {
	// Missing WorkspaceID
	cfg := validTestConfig()
	cfg.WorkspaceID = ""
	if _, err := seatling.New(cfg); err == nil {
		t.Fatal("expected error for empty WorkspaceID")
	}

	// Missing ProductID
	cfg = validTestConfig()
	cfg.ProductID = ""
	if _, err := seatling.New(cfg); err == nil {
		t.Fatal("expected error for empty ProductID")
	}

	// Empty PublicKeys
	cfg = validTestConfig()
	cfg.PublicKeys = nil
	if _, err := seatling.New(cfg); err == nil {
		t.Fatal("expected error for nil PublicKeys")
	}

	cfg.PublicKeys = map[string]string{}
	if _, err := seatling.New(cfg); err == nil {
		t.Fatal("expected error for empty PublicKeys")
	}

	// Empty key entry
	cfg = validTestConfig()
	cfg.PublicKeys = map[string]string{"": testPubKeyB64}
	if _, err := seatling.New(cfg); err == nil {
		t.Fatal("expected error for empty kid in PublicKeys")
	}

	// Embedded NUL byte in WorkspaceID
	cfg = validTestConfig()
	cfg.WorkspaceID = "ws_test\x00injected"
	if _, err := seatling.New(cfg); err == nil {
		t.Fatal("expected error for NUL byte in WorkspaceID")
	}

	// Embedded NUL byte in PublicKeys
	cfg = validTestConfig()
	cfg.PublicKeys = map[string]string{"kid\x00bad": testPubKeyB64}
	if _, err := seatling.New(cfg); err == nil {
		t.Fatal("expected error for NUL byte in PublicKeys")
	}

	// Cleartext HTTP non-loopback APIBaseURL must fail
	cfg = validTestConfig()
	cfg.APIBaseURL = "http://api.seatling.com"
	if _, err := seatling.New(cfg); err == nil {
		t.Fatal("expected error for non-loopback http:// APIBaseURL")
	}

	// Query / fragment / userinfo injection in APIBaseURL must fail
	for _, badURL := range []string{
		"https://api.seatling.com?leak=1",
		"https://api.seatling.com#frag",
		"https://user@api.seatling.com",
		"https://api.seatling.com/../evil",
	} {
		cfg = validTestConfig()
		cfg.APIBaseURL = badURL
		if _, err := seatling.New(cfg); err == nil {
			t.Fatalf("expected error for invalid APIBaseURL %q", badURL)
		}
	}
}

func TestHWID(t *testing.T) {
	hwid, err := seatling.GetHWID()
	if err != nil {
		t.Fatalf("failed to get HWID: %v", err)
	}
	if len(hwid) == 0 {
		t.Fatal("expected non-empty HWID string")
	}

	base := seatling.HWIDComponents{
		CPU:    "cpu-model-intel-1",
		Mobo:   "mobo-serial-asus-1",
		Disk:   "disk-uuid-samsung-1",
		OSUUID: "os-guid-win11-1",
	}

	// Identical components should score 100
	score, err := seatling.WeightedScore(base, base)
	if err != nil {
		t.Fatalf("WeightedScore failed: %v", err)
	}
	if score != 100 {
		t.Fatalf("expected score 100 for identical HWID, got %d", score)
	}

	// Single CPU upgrade (-25 pts) leaves 75 pts (passes threshold >= 70)
	currCPUUpgrade := base
	currCPUUpgrade.CPU = "cpu-model-intel-2"
	score, err = seatling.WeightedScore(base, currCPUUpgrade)
	if err != nil {
		t.Fatalf("WeightedScore failed: %v", err)
	}
	if score != 75 {
		t.Fatalf("expected score 75 for CPU upgrade, got %d", score)
	}

	// Motherboard swap (-35 pts) leaves 65 pts (fails threshold >= 70)
	currMoboSwap := base
	currMoboSwap.Mobo = "mobo-serial-gigabyte-1"
	score, err = seatling.WeightedScore(base, currMoboSwap)
	if err != nil {
		t.Fatalf("WeightedScore failed: %v", err)
	}
	if score != 65 {
		t.Fatalf("expected score 65 for mobo swap, got %d", score)
	}

	// Embedded NUL byte in HWID component must fail
	currNul := base
	currNul.CPU = "cpu\x00bad"
	if _, err := seatling.WeightedScore(base, currNul); err == nil {
		t.Fatal("expected error for NUL byte in HWIDComponents")
	}
}

func TestClientLifecycle(t *testing.T) {
	cfg := validTestConfig()
	client, err := seatling.New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("failed to close client: %v", err)
		}
	}()

	// 1. Session ID check
	sessionID := client.SessionID()
	if len(sessionID) == 0 {
		t.Fatal("expected non-empty SessionID")
	}

	// 2. Initialize
	status, err := client.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	// Initial state without valid cache should be NotActivated
	if status != seatling.StatusNotActivated {
		t.Logf("Initialize status: %s (%d)", status, status)
	}

	// 3. Read checks
	isAuth := client.IsAuthorized()
	if isAuth {
		t.Fatal("expected not authorized before activation")
	}

	isValid := client.IsValid()
	if isValid {
		t.Fatal("expected not valid before activation")
	}

	// 4. Entitlements default values & NUL byte fallback
	bVal := client.GetEntitlementBool("feature_enabled", true)
	if !bVal {
		t.Fatalf("expected default true, got %v", bVal)
	}
	if !client.GetEntitlementBool("bad\x00key", true) {
		t.Fatal("expected default true for NUL key")
	}

	iVal := client.GetEntitlementInt64("max_concurrency", 64)
	if iVal != 64 {
		t.Fatalf("expected default 64, got %d", iVal)
	}

	fVal := client.GetEntitlementFloat64("ratio_threshold", 0.75)
	if fVal != 0.75 {
		t.Fatalf("expected default 0.75, got %f", fVal)
	}

	// 5. Blocking checks with short, zero, and negative timeouts
	validBlocking := client.IsValidBlocking(50 * time.Millisecond)
	if validBlocking {
		t.Fatal("expected false for IsValidBlocking before activation")
	}
	if client.IsValidBlocking(0) {
		t.Fatal("expected false for IsValidBlocking(0)")
	}
	if client.IsValidBlocking(-10 * time.Millisecond) {
		t.Fatal("expected false for IsValidBlocking(-10ms)")
	}

	// 6. Activate with NUL byte must return error immediately
	if _, err := client.Activate("SEAT-XXXX\x00YYYY"); err == nil {
		t.Fatal("expected error for NUL byte in Activate licenseKey")
	}

	// 7. Multiple Close calls should be idempotent and subsequent operations return ErrClientClosed
	if err := client.Close(); err != nil {
		t.Fatalf("first explicit Close failed: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second idempotent Close failed: %v", err)
	}
	if status, err := client.Initialize(); !errors.Is(err, seatling.ErrClientClosed) || status != seatling.StatusNotActivated {
		t.Fatalf("expected ErrClientClosed and StatusNotActivated after Close, got status=%v, err=%v", status, err)
	}
}

func TestConcurrentReads(t *testing.T) {
	cfg := validTestConfig()
	client, err := seatling.New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	_, _ = client.Initialize()

	const numGoroutines = 20
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = client.IsAuthorized()
				_ = client.IsValid()
				_ = client.Status()
				_ = client.GetEntitlementBool("flag", false)
				_ = client.GetEntitlementInt64("limit", 100)
			}
		}()
	}

	wg.Wait()
}

func BenchmarkIsAuthorized(b *testing.B) {
	cfg := validTestConfig()
	client, err := seatling.New(cfg)
	if err != nil {
		b.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	_, _ = client.Initialize()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.IsAuthorized()
	}
}
