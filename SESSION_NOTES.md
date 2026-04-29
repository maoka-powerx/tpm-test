# TPM Sidecar — Session Notes & Reference

**Project:** Go TPM Smart Proxy Sidecar  
**Device:** Phoenix Contact VL3 UPC 2440 EDGE  
**TPM chip:** Infineon SLB9670 (discrete TPM 2.0, exposed at `/dev/tpmrm0`)  
**Go library:** `github.com/google/go-tpm v0.9.8`  
**Date:** 2026-04-29  

---

## What this project is

A Go binary that acts as the cryptographic engine and mTLS reverse proxy for an edge device.
It sits alongside a NestJS container in a Podman pod and handles everything security-related
so NestJS never touches private keys or TLS internals.

```
[Offline PMS] ──wss (mTLS)──► [Go sidecar :443] ──ws──► [NestJS :3000]
                                      │
                                      ├── /dev/tpmrm0 (Infineon TPM)
                                      └── :8080 (local HTTP API for NestJS)
```

---

## Why a custom Go app and not tpm2-tools?

### The hard blocker: the TLS handshake

When a PMS connects via mTLS, Go's `crypto/tls` performs the handshake. At a specific
moment it calls a `crypto.Signer` interface — a Go object with a `Sign()` method — to
prove the device's identity. That call happens **inside the same running process**,
synchronously, in memory.

`tpm2-tools` is a separate process. You cannot pass a callback into it. You cannot hook
it into `crypto/tls`. There is no way to make `tpm2 sign` participate in a live TLS
handshake — the handshake happens in microseconds and expects an in-process function
call, not a shell command.

**This alone makes the custom Go app mandatory.** Everything else is a bonus.

### The other reasons

**Scratch container** — `tpm2-tools` depends on the full TSS2 C library stack
(`libtss2-esys`, `libtss2-sys`, `libssl`, etc.). Cannot run in a `scratch` or
`distroless` container. The Go binary is fully static — no shared libraries, no libc.

**No shell** — The requirements say no shell in the container. `tpm2-tools` requires
bash/sh to invoke. Shell commands from Go also open command injection vulnerabilities.

**The HTTP API** — `tpm2-tools` cannot expose `POST /api/v1/generate-csr`. The Go app
IS the HTTP server. Same binary.

**Atomic operations** — `CreatePrimary → EvictControl → CSR signing` should be one
uninterruptible sequence on a single open TPM connection. Three separate `tpm2-tools`
processes could be raced or interrupted between steps.

**Live TLS cert reload** — When NestJS saves a new `ems.crt` and calls the reload
endpoint, the proxy must reload its TLS config without dropping connections. Requires
an in-process channel. A subprocess cannot do this.

**Observability** — Prometheus metrics, structured JSON logs, OTel traces live inside
the process. Per-request latency from `tpm2-tools` invocations is not possible.

### Summary

| Capability | `tpm2-tools` | Custom Go app |
|---|---|---|
| Runs in scratch container | No (needs libtss2, libssl) | Yes (static binary) |
| Participates in TLS handshake | **Impossible** | Yes (`crypto.Signer`) |
| Exposes HTTP API | No | Yes |
| No shell required | No | Yes |
| Atomic multi-step TPM ops | No (separate processes) | Yes (single connection) |
| Live TLS cert reload | No | Yes |
| Prometheus / OTel | No | Yes |

The requirement doc anticipated this: *"It must not rely on C-based PKCS#11 bridges"* —
that rules out not just PKCS#11 but the entire TSS2 C stack that `tpm2-tools` is built on.

---

## Issues found in requirements (requirements.txt vs requirements2.txt)

1. **API path conflict** — `requirements.txt` says `POST /generate-csr`,
   `requirements2.txt` says `POST /api/v1/generate-csr`. Use the versioned path.

2. **Missing TLS reload endpoint** — `requirements2.txt` Workflow 1 step 6 says
   "NestJS notifies Go to reload TLS config" but no endpoint is defined anywhere.
   Needs `POST /api/v1/reload-tls`.

3. **`/sign-payload` undefined in requirements2** — mentioned only in `requirements.txt`
   as optional. Needs a decision.

4. **Port 443 vs "drop all root"** — binding port 443 requires `CAP_NET_BIND_SERVICE`.
   The security section says drop all root. Fix: `setcap cap_net_bind_service=+ep /app/sidecar`
   in the Dockerfile, or use port 8443 internally and let the host NAT/redirect.

5. **No AuthValue = deliberate trade-off** — headless reboot recovery requires no PIN.
   This means any code running on the device can trigger TPM operations.
   Document this decision explicitly.

---

## Key concepts explained

### Why a TPM?
Normal approach: private key lives in RAM or on disk → can be stolen if device is compromised.
TPM approach: private key generated INSIDE the chip silicon → physically unreachable.
Even if someone clones the disk and dumps memory, the private key is gone.

The TPM is like a safe that signs documents for you but never lets you take the pen out.

### Why ECC P-256?
- Smaller keys than RSA for the same security level (256 bits ≈ RSA 3072 bits)
- Faster TLS handshakes on constrained edge hardware
- Less cellular bandwidth for certificates
- Natively supported by TPM 2.0, Go's TLS stack, and Step-CA

### What mTLS needs
Each side needs:
1. A private key (proves "I own this certificate")
2. A certificate signed by Step-CA (proves "I am who I claim to be")

The TPM holds the private key. Step-CA issues the certificate after seeing a CSR.

### What a CSR is
A Certificate Signing Request = a form sent to Step-CA containing:
- Your public key
- Your identity (commonName, etc.)
- A signature from your private key (proves you actually own the key pair)

Step-CA returns a `.crt` certificate. That certificate then lives on disk.
The private key stays in the TPM forever.

### TPM handle ranges (persistent storage)
```
0x81000000 – 0x8100FFFF  Owner/application space     ← OUR keys go here
0x81010000 – 0x8101FFFF  Endorsement/platform range  ← manufacturer EK
0x81020000 – 0x8102FFFF  Platform range              ← platform keys
```

### Transient vs persistent keys
- **Transient**: lives in TPM RAM only. Gone when the program exits or you flush the handle.
- **Persistent**: written to TPM non-volatile storage via `EvictControl`. Survives reboots.

For this project: all application keys MUST be persistent.

### How to delete a persistent key
```bash
# using tpm2-tools on the device
sudo tpm2_evictcontrol -C o -c 0x8100002A

# or in Go code (same EvictControl command, but ObjectHandle = the persistent handle itself)
tpm2.EvictControl{
    Auth:             tpm2.TPMRHOwner,
    ObjectHandle:     tpm2.NamedHandle{Handle: tpm2.TPMHandle(0x8100002A)},
    PersistentHandle: tpm2.TPMHandle(0x8100002A),
}.Execute(t)
```

TPM NV storage on the Infineon SLB9670 holds ~128 persistent objects.

---

## What exists on this device's TPM

Documented in detail in `tpm-key-inventory.md`.

### Short version:
```
0x81010000  Infineon Endorsement Key (EK)     RSA 2048, restricted, DO NOT TOUCH
0x81020000  Unknown platform key              ECC P-256, UserWithAuth=true (unknown password)
0x8100002A  OUR application key               ECC P-256, no password, signing-capable
```

---

## Code structure

```
tpm-test/
├── go.mod                         module: tpm-sidecar, go 1.22
├── main.go                        entry point (~30 lines)
├── sidecar                        compiled binary (cross-compiled for linux/amd64)
├── internal/
│   └── tpm/
│       ├── tpm.go                 core TPM operations (CreateKey)
│       └── inspect.go             debugging (ListPersistentKeys)
├── tpm-key-inventory.md           raw output + explanation of factory keys
└── SESSION_NOTES.md               this file
```

`internal/` is a special Go directory — packages inside it cannot be imported
by code outside this module. It signals "service component, not a library."

---

## Go concepts learned in this session

### Package visibility
```go
func CreateKey(...)   // capital C = exported = callable from other packages
func inspectHandle()  // lowercase i = unexported = private to this package
```
In Python: like `_private_method` but enforced by the compiler.

### Error handling (no exceptions in Go)
```go
result, err := someFunction()
if err != nil {
    return fmt.Errorf("context: %w", err)  // %w wraps the error (like Python's "raise X from Y")
}
```

### Defer (like Python's finally / context manager)
```go
defer tpm.Close()   // runs when the function returns, no matter what
// equivalent to Python's: with open(...) as tpm:
```

### go.mod = pyproject.toml
```
module tpm-sidecar      # module name (import path prefix)
go 1.22                 # minimum Go version
require (...)           # added automatically by "go get"
```

### Build commands
```bash
go get github.com/google/go-tpm@v0.9.8   # add dependency (like pip install)
go run .                                   # compile + run (like python main.py)
go build -o sidecar .                      # compile to binary
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o sidecar .  # cross-compile for edge device
```

### go-tpm v0.9 API pattern
Every TPM command is a struct with an Execute() method:
```go
// Instead of a function call like: tpm2.GetRandom(connection, 16)
// v0.9 uses:
rsp, err := tpm2.GetRandom{BytesRequested: 16}.Execute(t)
result := rsp.RandomBytes.Buffer   // response fields are also structs
```

---

## Key handle used

```
AppKeyHandle = 0x8100002A   (42 decimal = 0x2A in the low bytes)
```

This handle is the device's permanent identity for the lifetime of the device.
Do NOT change it after the certificate has been issued by Step-CA.

---

## What has been implemented

- [x] Random bytes from TPM (proof of concept)
- [x] List all persistent keys with full attribute dump
- [x] Inspect factory keys on the VL3 device
- [x] CreateKey — ECC P-256, persistent, idempotent (create-or-load pattern)

---

## Next steps (not yet implemented)

1. **GenerateCSR** — use the TPM key to sign a CSR and return it to NestJS
   - Input: `{ "commonName": "vl3-edge-01" }`
   - Output: PEM-encoded CSR string
   - File: add to `internal/tpm/tpm.go`

2. **HTTP API server on :8080** — NestJS calls this
   - `POST /api/v1/generate-csr`
   - `POST /api/v1/reload-tls`  ← missing from requirements, needs to be added
   - File: `internal/api/api.go`

3. **mTLS reverse proxy on :8443** — PMS connects here
   - Load `ems.crt` from `/shared/certs/ems.crt`
   - Use TPM as `crypto.Signer` for the TLS handshake
   - Forward decrypted WebSocket traffic to `ws://localhost:3000`
   - File: `internal/proxy/proxy.go`

4. **Config via environment variables**
   ```
   TPM_DEVICE=/dev/tpmrm0
   API_LISTEN=:8080
   PROXY_LISTEN=:8443
   CERT_PATH=/shared/certs/ems.crt
   ```

---

## Build and deploy reference

```bash
# on dev machine — cross-compile
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o sidecar .

# copy to edge device
scp sidecar admin@<edge-ip>:/tmp/sidecar

# on edge device
chmod +x /tmp/sidecar
sudo /tmp/sidecar
```

`sudo` required because `/dev/tpmrm0` is owned by the `tss` group.
In production: add the app user to the `tss` group instead of running as root.

---

## Library versions

| Library | Version | Why |
|---|---|---|
| `github.com/google/go-tpm` | v0.9.8 | Native Go TPM 2.0, no CGO, no PKCS#11 |
| `golang.org/x/sys` | v0.8.0 | Pulled in automatically by go-tpm |

No Prometheus, OTel, or other deps yet — those come with the API/proxy phase.
