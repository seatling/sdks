# AGENTS.md — Seatling Client SDKs

Tactical instructions and operational guidelines for AI coding agents working in the `seatling-sdks` repository.

---

## Overview & Architecture

`seatling-sdks` is a polyglot monorepo delivering official client SDKs for the **Seatling** software licensing and seat management platform. It implements the **Zero-Prompt Ed25519 Hybrid Hardware Anchor Architecture (V7)**.

### Repository Layout

- **`crates/seatling`**: Unified Rust Core and C-ABI engine. Produces `rlib`, `staticlib`, and `cdylib`.
  - Single source of truth for cryptographic algorithms (Ed25519, HKDF-SHA256, AES-256-GCM), weighted hardware quorum scoring (`threshold >= 70`), lock-free atomic cache snapshots, and offline lease validation.
  - Exposes C/C++17 RAII headers in `include/seatling/` (`seatling.h`, `seatling.hpp`).
  - Contains C++ integration tests in `tests/cpp/` built via CMake in `crates/seatling/build/`.
- **`crates/seatling-node`**: Unified Node.js and Electron SDK (`@seatling/node`).
  - High-performance N-API native bindings wrapping the Rust core with a TypeScript idiomatic client.
- **`crates/seatling-go`**: Unified Golang SDK (`github.com/seatling/seatling-sdk-go`).
  - Monolithic static CGO bindings (`CGO_ENABLED=1`) wrapping the Rust core C-ABI (`libseatling.a`) with zero dynamic library unpacking.
- **`openapi.yaml`**: Authoritative OpenAPI 3.1.0 contract specification for Seatling Cloud licensing APIs.
- **`HARDWARE_ANCHOR_V7.md` & `SDK_ARCHITECTURE.md`**: Normative specifications detailing cryptographic invariants and zero-prompt OS requirements.

---

## Setup & Environment Prerequisites

- **Rust**: Stable toolchain (>= 1.78) with `clippy` and `rustfmt` components:
  ```bash
  rustup component add clippy rustfmt
  ```
- **Node.js**: Node.js >= 20.0.0 and `npm`. Install dependencies for Node SDK:
  ```cmd
  cmd /c npm install --prefix crates/seatling-node
  ```
- **Go**: Go >= 1.22.0. Dependencies are managed via Go modules:
  ```bash
  go -C crates/seatling-go mod tidy
  ```
- **C++ / CMake**: CMake >= 3.15 with a C++17 compiler (MSVC on Windows, Clang/GCC on Unix).

---

## Validation Steps & Baseline Benchmarks

All contributions must satisfy the relevant validation suites. You can run unified monorepo commands from the repository root via npm, or run targeted toolchain commands:

### Top-Level Monorepo Commands
| Task | Command | Description |
| :--- | :--- | :--- |
| **Test Everything** | `cmd /c npm test` | Executes Rust core (14), Node SDK (36), CTest (2 targets), and Go SDK (4) |
| **Lint Everything** | `cmd /c npm run lint` | Executes Rust Clippy, Node TypeScript check, Go vet, OpenAPI lint, and BSL license validation |
| **Check Format** | `cmd /c npm run format:check` | Verifies formatting across Rust codebase (`cargo fmt --check`) |
| **Format Code** | `cmd /c npm run format` | Formats codebase (`cargo fmt`) |
| **Build Everything** | `cmd /c npm run build` | Builds Rust staticlib/cdylib, Node native addon, C++ targets, and Go SDK |
| **Stamp License Date** | `cmd /c npm run license:stamp` | Stamps BSL 1.1 Change Date (+4 years from today) across all LICENSE files |

### Individual Toolchain Benchmarks

| Validation Suite | Command | Expected Result |
| :--- | :--- | :--- |
| **Rust Core Tests** | `cargo test --workspace` | `14/14 passed` |
| **C++ Unit Tests** | `ctest --test-dir crates/seatling/build -C Release --output-on-failure` | `12/12 passed (100%)` |
| **Node.js SDK Tests** | `cmd /c npm test --prefix crates/seatling-node` | `36/36 passed` |
| **Node.js Linter** | `cmd /c npm run lint --prefix crates/seatling-node` | `0 errors (tsc --noEmit)` |
| **Go SDK Tests** | `go -C crates/seatling-go test -v ./...` | `4/4 passed` |
| **Go SDK Linter** | `go -C crates/seatling-go vet ./...` | `0 errors` |
| **Rust Clippy** | `cargo clippy --workspace --all-targets -- -D warnings` | `0 warnings` |
| **Rust Formatter** | `cargo fmt --all -- --check` | `Clean` |
| **OpenAPI Lint** | `cmd /c npx @redocly/cli lint openapi.yaml` | `0 errors, 0 warnings` |

---

## Targeted Workflows (Smallest Sensible Subset)

Always scope validations to the smallest affected blast radius. Do **not** run blanket sweeps across all languages when modifying an isolated component.

### 1. Working on Rust Core (`crates/seatling/src/**`)
- **Unit Validation**:
  ```bash
  cargo test -p seatling
  cargo clippy -p seatling --all-targets -- -D warnings
  cargo fmt --all -- --check
  ```
- **Downstream Verification**:
  - If changing the C-ABI or exported FFI symbols (`ffi.rs`, `lib.rs`, `types.rs`):
    1. Rebuild the Rust staticlib:
       ```bash
       cargo build --release -p seatling
       ```
    2. Re-compile and execute C++ tests:
       ```cmd
       cmake --build crates/seatling/build --config Release
       ctest --test-dir crates/seatling/build -C Release --output-on-failure
       ```
    3. Rebuild native Node addon and run Node tests:
       ```cmd
       cmd /c npm run build:native --prefix crates/seatling-node
       cmd /c npm test --prefix crates/seatling-node
       ```
  - If only internal Rust core logic changed (e.g., pure `hwid.rs` calculation or `jwt.rs` parsing), running `cargo test -p seatling` is sufficient for iterative development.

### 2. Working on Node.js / Electron SDK (`crates/seatling-node/**`)
- **TypeScript Only** (`crates/seatling-node/src/*.ts`, `crates/seatling-node/test/*.ts`):
  - **Do NOT** recompile C++ or run workspace-wide Rust clippy.
  - Run Node linter:
    ```cmd
    cmd /c npm run lint --prefix crates/seatling-node
    ```
  - Run Node test suite:
    ```cmd
    cmd /c npm test --prefix crates/seatling-node
    ```
- **Native Rust N-API Layer** (`crates/seatling-node/src/lib.rs`):
  - Rebuild native addon and execute tests:
    ```cmd
    cmd /c npm run build:native --prefix crates/seatling-node
    cmd /c npm test --prefix crates/seatling-node
    ```

### 3. Working on C++ SDK & Headers (`crates/seatling/include/**`, `crates/seatling/tests/cpp/**`)
- **Do NOT** run Node.js tests or OpenAPI linting.
- Rebuild C++ targets:
  ```cmd
  cmake --build crates/seatling/build --config Release
  ```
- Execute C++ unit tests:
  ```cmd
  ctest --test-dir crates/seatling/build -C Release --output-on-failure
  ```

### 4. Working on Go SDK (`crates/seatling-go/**`)
- **Do NOT** recompile C++ or run workspace-wide Rust clippy if only Go logic changed.
- Run Go linter:
  ```bash
  go -C crates/seatling-go vet ./...
  ```
- Run Go test suite:
  ```bash
  go -C crates/seatling-go test -v ./...
  ```
- If changing the C-ABI in `crates/seatling`, rebuild the static library first:
  - On Linux/macOS: `cargo build --release -p seatling`
  - On Windows for Go CGO (GNU ABI): `cargo build --release --target x86_64-pc-windows-gnu -p seatling`

### 5. Working on OpenAPI Contract (`openapi.yaml`)
- **Do NOT** invoke Rust or C++ toolchains.
- Validate specification:
  ```cmd
  cmd /c npx @redocly/cli lint openapi.yaml
  ```

---

## Core Invariants & Boundaries

1. **Zero-Prompt Guarantee**:
   - Never introduce code that prompts interactive OS credential dialogs or requires special entitlements (e.g. no macOS Keychain ACL prompts, silent DPAPI on Windows).
2. **Lock-Free Read Path**:
   - `is_authorized()` and `get_entitlement()` must maintain sub-microsecond latency (< 0.01ms / ~50ns) using atomic snapshots (`ArcSwap`). Never introduce disk I/O, network requests, or mutex contention into read checks.
3. **Multi-Workspace Key Isolation**:
   - Workspace signing keys are isolated. SDK initialization requires explicit public key mappings (`public_keys: { "<kid>": "<base64/base64url>" }`). Fails fast with `StatusCode::TamperOrSignatureInvalid` if keys are missing or invalid.
4. **Weighted Hardware Quorum**:
   - Hardware matching requires a fuzzy quorum score `>= 70` (Mobo = 35 pts, CPU = 25 pts, Disk = 20 pts, OS UUID = 20 pts). Motherboard swaps fail verification; individual component upgrades pass seamlessly.

---

## Code Style & PR Guidelines

- **Rust**:
  - Run `cargo fmt --all` and ensure zero warnings with `cargo clippy --workspace --all-targets -- -D warnings`.
  - Use idiomatic error propagation via `Result<T, SeatlingError>`.
- **TypeScript**:
  - Enforce strict typing with no implicit `any`. Verify with `tsc --noEmit`.
  - Follow camelCase naming for TypeScript and snake_case for Rust core exports.
- **Commit Messages**:
  - Strictly adhere to Conventional Commits format for compatibility with `release-please`:
    - `feat(core): add hardware metric normalizer`
    - `fix(node): handle missing storage directory gracefully`
    - `test(cpp): verify fuzzy quorum boundary on component upgrade`
    - `docs: update hardware anchor specification`
