# TPM Key Inventory — VL3-UPC-Edge-2038152548

Device: Phoenix Contact VL3 UPC 2440 EDGE
TPM chip: Infineon SLB9670 (discrete TPM 2.0)
Date inspected: 2026-04-29
Tool: `sidecar` binary built from `main.go` (go-tpm v0.9.8)

---

## Raw output

```
═══════════════════════════════════════
  TPM Persistent Key Inventory
  Total: 2 key(s) found
═══════════════════════════════════════

┌─ Handle: 0x81010000  (Endorsement/platform range)
│
│  ── Algorithm ──────────────────────────────
│  Name algorithm : SHA-256
│  Key type       : RSA
│  Key size       : 2048 bits
│  Signing scheme : null (parent/storage key)
│  Exponent       : 65537
│  Modulus (hex)  : c1f40b89007a3948f12e9df55ed8c070...
│  Modulus length : 256 bytes (2048 bits)
│
│  ── Authorization ──────────────────────────
│  Auth policy    : 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
│
│  ── Attributes ─────────────────────────────
│  FixedTPM           : true  ← private key is hardware-bound to this chip
│  FixedParent        : true
│  TPM-generated      : true  ← key was created inside the TPM silicon
│  UserWithAuth       : false
│  AdminWithPolicy    : true
│  NoDA (no lockout)  : false
│  Restricted         : true  ← true = likely a platform/manufacturer key
│  SignEncrypt        : false
│  Decrypt            : true
│  STClear            : false
│
│  ── Identity ───────────────────────────────
│  TPM Name (hex)     : 000ba15f7fad4f4d60e1f04c5ce63afcaab8d14ad1d47ab3555c23540375a9ce9460
└─────────────────────────────────────────

┌─ Handle: 0x81020000  (Platform range)
│
│  ── Algorithm ──────────────────────────────
│  Name algorithm : SHA-256
│  Key type       : ECC
│  Curve          : P-256 (NIST)
│  Signing scheme : null (parent/storage key)
│  KDF scheme     : null
│  Public key X   : f26e74c8abc7592a625dc5ca722a2ce003e8c4642192c7bb386f6784fbc5720b
│  Public key Y   : 449826f3f4df89ed51d8e0bac4f640b3735e80993159783f31d24069dd1ec29f
│
│  ── Authorization ──────────────────────────
│  Auth policy    : none
│
│  ── Attributes ─────────────────────────────
│  FixedTPM           : true  ← private key is hardware-bound to this chip
│  FixedParent        : true
│  TPM-generated      : true  ← key was created inside the TPM silicon
│  UserWithAuth       : true
│  AdminWithPolicy    : true
│  NoDA (no lockout)  : false
│  Restricted         : false  ← true = likely a platform/manufacturer key
│  SignEncrypt        : true
│  Decrypt            : false
│  STClear            : false
│
│  ── Identity ───────────────────────────────
│  TPM Name (hex)     : 000b54934c0b5616497b192bb13e5f0f14e9df15af205452f8bbb002719606c0380d
└─────────────────────────────────────────
```

---

## Key 1 — `0x81010000` — Infineon Endorsement Key (EK)

**What it is:** The factory-burned Endorsement Key, created by Infineon at manufacture time.
Its purpose is device attestation — proving to a remote party that this is a genuine TPM chip.

| Attribute | Value | Meaning |
|---|---|---|
| Type | RSA 2048 | Older standard, common for EKs |
| Signing scheme | null | Not a signing key — it's a decryption/unwrapping key |
| Decrypt | true | Used to unwrap secrets sent to this device |
| SignEncrypt | false | Cannot sign arbitrary data |
| Restricted | true | Can only process TPM-internally-generated data |
| UserWithAuth | false | Cannot be used with a simple password |
| AdminWithPolicy | true | Requires a policy session to use |
| Auth policy | `8371...aa` | **Standard TCG EK policy** — a well-known hash from the TPM spec that locks the key to the Endorsement hierarchy. Requires Step-CA's TPM attestation flow (TPM2_PolicySecret with endorsement hierarchy auth). |

**Action: leave alone.** This key is the manufacturer's chain-of-trust anchor.
It is used in TPM remote attestation workflows (e.g. verifying device genuineness with a CA),
not for application-level signing or mTLS.

---

## Key 2 — `0x81020000` — Unknown Platform/Application Key (ECC P-256)

**What it is:** An ECC P-256 key of unknown origin — likely provisioned by Phoenix Contact
or a platform setup tool. Its attributes say it is capable of signing arbitrary data.

| Attribute | Value | Meaning |
|---|---|---|
| Type | ECC P-256 | Correct curve for our application |
| Signing scheme | null | Flexible — scheme chosen at signing time (ECDSA, etc.) |
| Restricted | false | Can sign arbitrary external data (unlike the EK) |
| SignEncrypt | true | Signing-capable |
| Decrypt | false | Not a decryption key |
| UserWithAuth | true | Requires an auth value (password) to use |
| Auth policy | none | No policy — but the auth value is unknown |

**Action: leave alone.** Although the key attributes are compatible with our use case,
`UserWithAuth: true` means a password was set when the key was created.
That password is unknown. Attempting to use the key would fail silently or trigger
dictionary attack lockout after repeated failures.

---

## Handle map — this device

```
0x81000001  ← OUR application key goes here  (currently empty, clean)
0x81010000  ← Infineon EK — DO NOT TOUCH
0x81020000  ← Phoenix Contact key — DO NOT TOUCH
```

The `0x81000000–0x8100FFFF` range (Owner/application space) is completely empty.
Our key will be created at `0x81000001` with:
- Algorithm: ECC P-256
- Scheme: ECDSA with SHA-256
- No auth value (headless, for automatic reboot recovery)
- Persistent (survives reboots via EvictControl)
