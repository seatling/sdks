# Seatling Client SDKs

[![CI — Rust SDK](https://github.com/seatling/seatling-sdks/actions/workflows/ci-rust.yml/badge.svg)](https://github.com/seatling/seatling-sdks/actions/workflows/ci-rust.yml)
[![CI — C++ SDK](https://github.com/seatling/seatling-sdks/actions/workflows/ci-cpp.yml/badge.svg)](https://github.com/seatling/seatling-sdks/actions/workflows/ci-cpp.yml)
[![CI — Node.js SDK](https://github.com/seatling/seatling-sdks/actions/workflows/ci-node.yml/badge.svg)](https://github.com/seatling/seatling-sdks/actions/workflows/ci-node.yml)
[![CI — Go SDK](https://github.com/seatling/seatling-sdks/actions/workflows/ci-go.yml/badge.svg)](https://github.com/seatling/seatling-sdks/actions/workflows/ci-go.yml)
[![OpenAPI 3.1.0](https://img.shields.io/badge/OpenAPI-3.1.0-green.svg)](openapi.yaml)
[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](LICENSE)

Official client SDKs for the **Seatling** software licensing and seat management platform. Engineered for software creators building **desktop applications (Windows, macOS, Linux)**, **creative tools / audio plugins (VST3, AU, AAX)**, **developer utilities**, and **native services**.

## Quickstart

### Node.js / Electron (`@seatling/node`)

The Node.js SDK executes directly against the compiled Rust core via N-API with zero backwards-compatibility overhead or pure-JS duplication:

```bash
npm install @seatling/node
```

```typescript
import { SeatlingClient } from '@seatling/node';

const client = new SeatlingClient({
  workspaceId: 'ws_01j8k9m0n1p2q3r4s5t6u7v8w9',
  productId: 'prod_creative_suite',
  publicKeys: {
    // Authoritative kid and Base64URL-encoded Ed25519 public key from the Creator Dashboard:
    'prod_creative_suite_2026_v1': 'u8A_wX09G7V8B3_N8Q4E5F6G7H8I9J0K1L2M3N4O5P6',
  },
  appVersion: '2.1.0',
});

// 1. Instant non-blocking startup (< 1ms, 0 network I/O)
const lease = client.initialize();

// 2. High-frequency hot-path checks (< 0.01ms / ~50ns)
if (client.isAuthorized()) {
  const maxExportRes = client.getEntitlement<number>('max_export_res', 1080);
} else {
  // Developer decides what to do if license cannot be verified:
  console.log('Application running in evaluation mode. Status:', lease.status);
}

// 3. Online activation (UI event)
async function onActivate(key: string) {
  const result = await client.activate(key);
  if (!result.success && result.portalUrl) {
    console.log('Manage seats at:', result.portalUrl);
  }
}

// 4. Graceful shutdown on app quit
// client.shutdown();
```

---

### C++17 Desktop / Native (`crates/seatling/include`)

Modern C++17 RAII interface linking statically to the compiled Seatling Rust staticlib (`seatling.lib` / `libseatling.a`) with zero runtime external DLL dependencies:

```cpp
#include <iostream>
#include "seatling/seatling.hpp"

int main() {
    seatling::SeatlingConfig cfg;
    cfg.workspace_id = "ws_01j8k9m0n1p2q3r4s5t6u7v8w9";
    cfg.product_id = "prod_creative_app";
    // Authoritative kid and Base64URL-encoded public key from Creator Dashboard
    cfg.public_keys["prod_creative_app_2026_v1"] = "u8A_wX09G7V8B3_N8Q4E5F6G7H8I9J0K1L2M3N4O5P6";
    cfg.app_version = "1.0.0";

    seatling::SeatlingClient client(cfg);

    // 1. Initialize offline cache (< 1ms, non-blocking, zero network I/O)
    auto status = client.initialize();

    // 2. Ultra-fast lock-free check in render loops or worker threads (< 0.01ms)
    if (client.is_authorized()) {
        int64_t max_res = client.get_entitlement_i64("max_resolution", 1080);
        std::cout << "Running with authorized seat. Max resolution: " << max_res << std::endl;
    } else {
        // Developer handles unauthorized state according to their application policy
        std::cout << "License status: " << seatling::status_to_string(status) << std::endl;
    }

    // 3. Graceful shutdown on exit
    client.shutdown();

    return 0;
}
```

Headers are located at [`crates/seatling/include/seatling/`](./crates/seatling/include/seatling).

---

### Golang Desktop / Services (`github.com/seatling/seatling-sdk-go`)

Monolithic statically linked distribution model (`CGO_ENABLED=1`) executing against the compiled Rust core with sub-microsecond lock-free reads (~40ns), zero runtime DLL extraction (immunized against DLL hijacking), and seamless cross-compilation via `zig cc`:

```bash
go get github.com/seatling/seatling-sdk-go
```

```go
package main

import (
	"fmt"
	"github.com/seatling/seatling-sdk-go"
)

func main() {
	client, err := seatling.New(seatling.Config{
		WorkspaceID: "ws_01j8k9m0n1p2q3r4s5t6u7v8w9",
		ProductID:   "prod_creative_app",
		PublicKeys: map[string]string{
			"prod_creative_app_2026_v1": "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=",
		},
		AppVersion: "1.0.0",
	})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	// 1. Initialize offline cache (< 1ms, non-blocking, zero network I/O)
	status, _ := client.Initialize()

	// 2. Lock-free check in request handlers, worker pools, or CLIs (< 0.0002ms)
	if client.IsAuthorized() {
		maxWorkers := client.GetEntitlementInt64("max_workers", 16)
		fmt.Println("Running with authorized seat. Max workers:", maxWorkers)
	} else {
		fmt.Println("Evaluation mode. Status:", status)
	}
}
```

SDK source is located at [`crates/seatling-go/`](./crates/seatling-go).

---

## Repository Structure

```text
seatling-sdks/
├── .github/
│   └── workflows/
│       ├── ci.yml                 # Multi-platform CI (OpenAPI, Rust core, Node SDK, C++ SDK, Go SDK)
│       ├── publish-release.yml    # Multi-platform binary compilation, release assets, & NPM publishing
│       ├── mirror.yml             # Dedicated Go SDK repository mirroring (seatling/sdk-go)
│       └── release-please.yml     # Release Please automated versioning & release orchestration
├── crates/
│   ├── seatling/                  # Rust Core Engine & C-ABI (rlib, staticlib, cdylib)
│   │   ├── include/seatling/      # C & C++17 RAII headers (seatling.h, seatling.hpp)
│   │   ├── src/                   # Rust core source code (JWT, Keystore, HWID, Verifier, Client)
│   │   ├── tests/                 # Rust unit tests & C++ CMake integration test
│   │   └── examples/              # C++ integration example
│   ├── seatling-node/             # Unified Node.js & Electron SDK (@seatling/node)
│   │   ├── package.json           # NPM package definition (published to npm)
│   │   ├── src/                   # Rust N-API bindings & TypeScript wrapper source
│   │   └── test/                  # Node.js test suite
│   └── seatling-go/               # Unified Golang SDK (github.com/seatling/seatling-sdk-go)
│       ├── go.mod                 # Go module definition
│       ├── client.go              # Thread-safe SeatlingClient wrapper
│       ├── hwid.go                # Hardware anchor & fuzzy quorum calculation
│       ├── internal/bin/          # Embedded native libraries (//go:embed)
│       ├── internal/loader/       # CGO-free dynamic library loader (syscall / purego)
│       └── examples/              # Standalone Go integration example
├── openapi.yaml                   # OpenAPI 3.1.0 Contract Specification
└── Cargo.toml                     # Cargo Workspace definition
```

---

## Development & Monorepo Tooling

The root [`package.json`](./package.json) orchestrates cross-ecosystem testing, linting, formatting, and building across Rust, C++, and Node.js:

```bash
# 1. Run all test suites (Rust 14/14, Node.js 36/36, CTest 2/2 targets)
npm test

# 2. Run all linters (Rust Clippy, Node.js TypeScript tsc --noEmit, Redocly OpenAPI 3.1.0)
npm run lint

# 3. Check and format code (cargo fmt)
npm run format:check
npm run format

# 4. Build all artifacts (Rust core, Node.js native addon, C++ targets)
npm run build
```

Individual sub-targets can also be run independently (e.g. `npm run test:node`, `npm run test:rust`, `npm run test:cpp`, `npm run lint:node`, `npm run lint:rust`, `npm run lint:openapi`).

---

## License

Business Source License 1.1 (BSL 1.1). Please refer to the [LICENSE](./LICENSE) file for the full license text.