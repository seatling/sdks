package main

import (
	"fmt"
	"log"

	"github.com/seatling/seatling-sdk-go"
)

func main() {
	fmt.Println("=== Seatling Go SDK Standalone Integration Example ===")

	// 1. Hardware Anchor Fingerprint (< 1ms, zero-prompt OS metrics)
	hwid, err := seatling.GetHWID()
	if err != nil {
		log.Fatalf("Failed to calculate HWID: %v", err)
	}
	fmt.Printf("[HWID] Current Hardware Anchor: %s\n", hwid)

	// 2. Initialize Seatling Client
	cfg := seatling.Config{
		WorkspaceID: "ws_01j8k9m0n1p2q3r4s5t6u7v8w9",
		ProductID:   "prod_enterprise_server",
		PublicKeys: map[string]string{
			"prod_key_2026_v1": "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=",
		},
		AppVersion: "1.0.0",
	}

	client, err := seatling.New(cfg)
	if err != nil {
		log.Fatalf("Failed to construct SeatlingClient: %v", err)
	}
	defer client.Close()

	// 3. Instant startup offline cache initialization (< 1ms, non-blocking)
	status, err := client.Initialize()
	if err != nil {
		log.Fatalf("Initialization error: %v", err)
	}
	fmt.Printf("[Startup] Offline Lease Status: %s (%d)\n", status, status)
	fmt.Printf("[Session] Session ID: %s\n", client.SessionID())

	// 4. Ultra-fast lock-free read check (< 100ns)
	if client.IsAuthorized() {
		maxWorkers := client.GetEntitlementInt64("max_workers", 8)
		allowExport := client.GetEntitlementBool("allow_export", true)
		fmt.Printf("[Authorized] Application unlocked! max_workers=%d, allow_export=%v\n", maxWorkers, allowExport)
	} else {
		fmt.Println("[Evaluation Mode] Application running in trial/unauthorized mode.")
	}

	fmt.Println("=== Done ===")
}
