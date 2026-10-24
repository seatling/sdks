# Seatling Golang SDK (`seatling-sdk-go`)

Official Golang client SDK for the **Seatling** software licensing and seat management platform. Engineered for Go developers building **standalone desktop apps**, **microservices**, **developer CLIs**, and **hardened cloud services**.

Powered directly by the authoritative Seatling Rust core engine with the **Zero-Prompt Ed25519 Hybrid Hardware Anchor Architecture (V7)**.

---

## Architecture & Security Model

The Seatling Go SDK uses **monolithic static linking via CGO** (`libseatling.a`):

- **Zero DLL Hijacking**: Does **not** unpack dynamic libraries (`.dll`, `.so`, `.dylib`) to writable directories (`%LOCALAPPDATA%`, `~/.cache`, or `/tmp`) at runtime. The security surface of search-order poisoning and symlink attacks is completely eliminated.
- **Single Self-Contained Binary**: Produces a standard, monolithic executable artifact.
- **Enterprise & Container Hardened**: Runs seamlessly in read-only root filesystems (`read_only: true`), immutable containers, and Kubernetes pods with `noexec` volume policies.
- **Zero EDR / Antivirus Alerts**: Avoids runtime executable dropping heuristics flagged by CrowdStrike, SentinelOne, or Windows Defender.
- **Sub-Microsecond Lock-Free Hot Path**: `IsAuthorized()` executes in **~40ns** with **0 heap allocations** via atomic cache snapshots (`ArcSwap`).

---

## Installation

```bash
go get github.com/seatling/seatling-sdk-go
```

---

## Building Your Application

Because `seatling-sdk-go` statically links the Rust core engine, **`CGO_ENABLED=1` is required** during compilation.

### 1. Local Native Compilation (Same OS as Target)

If building on your host OS with standard development tools installed:

- **Linux**: Requires `gcc` (`apt install build-essential` or `dnf groupinstall "Development Tools"`).
  ```bash
  CGO_ENABLED=1 go build -o myapp main.go
  ```
- **macOS**: Requires Xcode Command Line Tools (`xcode-select --install`).
  ```bash
  CGO_ENABLED=1 go build -o myapp main.go
  ```
- **Windows**: Requires a GCC-compatible toolchain (e.g. [w64devkit](https://github.com/skeeto/w64devkit), MinGW-w64, or Zig).
  ```cmd
  set CGO_ENABLED=1
  go build -o myapp.exe main.go
  ```

---

### 2. Universal Cross-Compilation via Zig CC (`zig cc`)

Standard Go makes pure-Go cross-compilation easy, but CGO traditionally requires heavy cross-GCC toolchains. The modern industry standard solution is **[Zig](https://ziglang.org/)**.

Zig ships with a powerful, zero-dependency drop-in C compiler (`zig cc`) that can cross-compile CGO code to **any target operating system and architecture** out of the box from a single ~40MB binary.

#### A. Install Zig (One-Time Setup)
- **macOS**: `brew install zig`
- **Windows**: `winget install zig.zig`
- **Linux**: `snap install zig --classic --beta` or download standalone binary from [ziglang.org/download](https://ziglang.org/download/).

#### B. Cross-Compilation Commands

From **any host OS** (Windows, macOS, or Linux), you can target any platform:

| Target Platform | Command |
| :--- | :--- |
| **Linux AMD64** | `CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC="zig cc -target x86_64-linux-gnu" go build -o myapp-linux main.go` |
| **Linux ARM64** | `CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC="zig cc -target aarch64-linux-gnu" go build -o myapp-linux-arm64 main.go` |
| **Windows AMD64** | `CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC="zig cc -target x86_64-windows-gnu" go build -o myapp.exe main.go` |
| **macOS Apple Silicon (ARM64)** | `CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC="zig cc -target aarch64-macos" go build -o myapp-darwin-arm64 main.go` |
| **macOS Intel (x86_64)** | `CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 CC="zig cc -target x86_64-macos" go build -o myapp-darwin-x64 main.go` |

> [!TIP]
> **macOS Universal Binary (Fat Binary)**:
> To ship a single binary supporting both Apple Silicon and Intel Macs:
> ```bash
> CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC="zig cc -target aarch64-macos" go build -o myapp-arm64 main.go
> CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 CC="zig cc -target x86_64-macos" go build -o myapp-x64 main.go
> lipo -create -output myapp-universal myapp-arm64 myapp-x64
> ```

---

### 3. Makefile Helper

To simplify builds for your team, add this `Makefile` to your project:

```makefile
.PHONY: build build-linux build-windows build-darwin

# Native build
build:
	CGO_ENABLED=1 go build -v -o bin/myapp main.go

# Cross-compilation using Zig CC
build-linux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC="zig cc -target x86_64-linux-gnu" go build -o bin/myapp-linux main.go

build-windows:
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC="zig cc -target x86_64-windows-gnu" go build -o bin/myapp.exe main.go

build-darwin:
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC="zig cc -target aarch64-macos" go build -o bin/myapp-darwin-arm64 main.go
```

---

### 4. Docker / Container Builds (Scratch & Distroless)

Because the resulting binary is completely self-contained with no runtime dynamic dependencies, you can run it inside a minimal `scratch` or `distroless` container image:

```dockerfile
# Build Stage
FROM golang:1.23-alpine AS builder

# Install build tools & Zig for cross-compilation
RUN apk add --no-cache git build-base zig

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build self-contained monolithic binary
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC="zig cc -target x86_64-linux-gnu" \
    go build -ldflags="-s -w" -o /app/server main.go

# Production Stage (Read-only, Scratch, Zero attack surface)
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /app/server /server
USER nonroot:nonroot

ENTRYPOINT ["/server"]
```

---

## Code Quickstart

```go
package main

import (
	"fmt"
	"log"

	"github.com/seatling/seatling-sdk-go"
)

func main() {
	// 1. Configure the Seatling Client
	cfg := seatling.Config{
		WorkspaceID: "ws_01j8k9m0n1p2q3r4s5t6u7v8w9",
		ProductID:   "prod_enterprise_suite",
		PublicKeys: map[string]string{
			// Authoritative kid and Base64-encoded Ed25519 verifying key from Creator Dashboard
			"prod_key_2026_v1": "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=",
		},
		AppVersion: "1.0.0",
	}

	client, err := seatling.New(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize Seatling client: %v", err)
	}
	defer client.Close()

	// 2. Instant offline cache initialization (< 1ms, non-blocking, zero network I/O)
	status, err := client.Initialize()
	if err != nil {
		log.Fatalf("Initialization error: %v", err)
	}
	fmt.Printf("[License Status] %s\n", status)

	// 3. High-frequency hot-path authorization check (~40ns, 0 heap allocs)
	// Safe to execute inside HTTP middleware, gRPC interceptors, or rendering loops
	if client.IsAuthorized() {
		maxWorkers := client.GetEntitlementInt64("max_workers", 16)
		allowExport := client.GetEntitlementBool("allow_export", true)
		fmt.Printf("Authorized seat! Max workers: %d, Export: %v\n", maxWorkers, allowExport)
	} else {
		// Handle unauthorized state according to your application policy (e.g. evaluation mode)
		fmt.Println("Running in trial / evaluation mode.")
	}

	// 4. Online Activation (e.g. on license key submission)
	// success, err := client.Activate("SEAT-XXXX-XXXX-XXXX")
	// if err != nil || !success {
	//     log.Println("Activation failed")
	// }
}
```

---

## Hardware Fingerprinting & Quorum

The SDK implements the **Zero-Prompt Ed25519 Hybrid Hardware Anchor Architecture (V7)**:

```go
// Derive authoritative composite hardware anchor (< 1ms, zero OS elevation dialogs)
hwid, err := seatling.GetHWID()
if err != nil {
    log.Fatalf("Failed to get HWID: %v", err)
}
fmt.Println("Machine HWID Fingerprint:", hwid)

// Evaluate hardware changes using weighted fuzzy quorum scoring (0 to 100)
// Verification threshold >= 70 (Motherboard = 35 pts, CPU = 25 pts, Disk = 20 pts, OS UUID = 20 pts)
score, err := seatling.WeightedScore(baselineComponents, currentComponents)
if err != nil {
    log.Fatal(err)
}
if score >= 70 {
    fmt.Println("Hardware quorum verified:", score)
}
```

---

## Benchmark Comparison

| Operation | Dynamic Unpacking (`purego`) | **Monolithic Static CGO (This SDK)** | Improvement |
| :--- | :--- | :--- | :--- |
| **`IsAuthorized()` Latency** | `183.9 ns/op` | **`~40.0 ns/op`** | **~4.6x faster** |
| **Heap Allocations** | `3 allocs/op (40 B/op)` | **`0 allocs/op (0 B/op)`** | **Zero GC pressure** |
| **Security Risk (DLL Hijack)** | Vulnerable in shared `/tmp` | **Immunized (0 dynamic files)** | **Enterprise Grade** |
| **Read-Only / Scratch Containers** | Fails (`permission denied`) | **100% Compatible** | **Production Ready** |

---

## License

Business Source License 1.1 (BSL 1.1). See the [LICENSE](./LICENSE) file for details.
