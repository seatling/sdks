# @seatling/node

Official Seatling Client SDK for Node.js and Electron applications. Implements the **Zero-Prompt Ed25519 Hybrid Hardware Anchor Architecture (V7)**.

---

## Overview

`@seatling/node` delivers native license verification, seat management, and entitlement querying for creative desktop applications, Electron apps, CLI tools, and Node.js services.

### Core Features

- **Lock-Free Authorization Check**: Atomic cache read path (`isAuthorized()`, `isValid()`) executing in `< 0.01ms` (~20–50ns).
- **Zero-Prompt Hardware Sealing**: Machine-bound hardware anchor (weighted quorum score $\ge 70$) with hardware-sealed Ed25519 key storage using Windows DPAPI (`CRYPTPROTECT_UI_FORBIDDEN`), macOS IOKit, and Linux DMI.
- **Native Binary Protection**: Critical cryptographic operations (HWID collection, AES-256-GCM unsealing, EdDSA verification) run in precompiled native machine code (`.node`), preventing script editing inside unpacked Electron `app.asar` archives.
- **Offline Grace Evaluation**: Tamper-proof offline grace engine with anti-clock-rollback protection.

---

## Installation

```bash
npm install @seatling/node
```

Prerequisites: Node.js >= 20.0.0.

---

## Quick Start

```typescript
import { SeatlingClient, SeatlingConfig } from '@seatling/node';

const config: SeatlingConfig = {
  workspaceId: 'ws_gumroad_creator',
  productId: 'prod_synth_v1',
  appVersion: '2.4.1',
  publicKeys: {
    // Dedicated workspace Ed25519 public keys indexed by kid from Creator Dashboard
    ws_gumroad_creator_2026_v1: 'u8A_wX09G7V8B3_N8Q4E5F6G7H8I9J0K1L2M3N4O5P6',
  },
};

// 1. Initialize client synchronously on startup (< 1ms)
const seatling = SeatlingClient.init(config);

// 2. High-frequency hot-path authorization check (< 0.01ms)
if (seatling.isAuthorized()) {
  console.log('App is licensed and authorized');
}

// 3. Query signed entitlements with typed fallbacks
const hasProDSP = seatling.getEntitlement('pro_dsp', false);
const maxOversampling = seatling.getEntitlement('max_oversampling', 2);
console.log(`Pro DSP: ${hasProDSP}, Oversampling: ${maxOversampling}`);

// 4. Activate a license key (cold path)
async function handleActivation(licenseKey: string) {
  const result = await seatling.activate(licenseKey);
  if (result.success) {
    console.log(`Activated seat: ${result.seatId}`);
  } else {
    console.error(`Activation rejected: ${result.status} - ${result.message}`);
    if (result.portalUrl) {
      console.log(`Manage seats at: ${result.portalUrl}`);
    }
  }
}
```

---

## API Reference

### Dual Query Surface

- `seatling.isAuthorized(): boolean`: Lock-free, zero-allocation check of current authorization status (< 0.01ms).
- `seatling.isValid(): boolean`: Alias for `isAuthorized()`.
- `seatling.status(): LicenseStatusCode`: Returns current license status code (e.g. `OK`, `NOT_ACTIVATED`, `OFFLINE_GRACE_EXPIRED`, `REQUIRES_PORTAL_DEACTIVATION`).
- `seatling.isValidBlocking(timeoutMs?: number): boolean`: Pre-flight check that unseals local keystore, verifies offline grace, and triggers an online heartbeat if needed (default timeout: 8000ms).
- `seatling.statusBlocking(timeoutMs?: number): LeaseStatus`: Returns full lease status struct after pre-flight check.

### Entitlements

- `seatling.getEntitlement<T extends boolean | number | string>(key: string, defaultValue: T): T`
- `seatling.getEntitlementBool(key: string, defaultValue?: boolean): boolean`
- `seatling.getEntitlementNumber(key: string, defaultValue?: number): number`
- `seatling.getEntitlementString(key: string, defaultValue?: string): string`

### Lifecycle & Heartbeat

- `seatling.activate(licenseKey: string): Promise<ActivationResult>`: Generates Ed25519 Proof-of-Possession JWT signed by the hardware-sealed keystore and activates the seat slot.
- `seatling.heartbeatNow(): Promise<LeaseStatus>`: Performs 1-RTT mutual-challenge heartbeat with server-echoed nonce.
- `seatling.heartbeatWithTimeout(timeoutMs?: number): Promise<LeaseStatus>`
- `seatling.deactivate(): Promise<boolean>`: Clears local lease and gracefully releases seat allocation.
- `seatling.shutdown(): void`: Stops background heartbeat timer worker.

---

## License

BSL 1.1 (Business Source License 1.1). Please refer to the [LICENSE](./LICENSE) file for the full license text.
