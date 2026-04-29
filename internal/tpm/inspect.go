// Debugging and inspection utilities for the TPM.
// Not used in normal operation — call these when you need to audit
// what keys exist on a device or diagnose TPM state.
package tpm

import (
	"encoding/hex"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// ListPersistentKeys prints detailed information about every persistent key
// currently stored in the TPM. READ-ONLY — never modifies the TPM.
func ListPersistentKeys(tpmPath string) error {

	t, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("opening TPM: %w", err)
	}
	defer t.Close()

	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      0x81000000,
		PropertyCount: 254,
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("GetCapability: %w", err)
	}

	handles, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		return fmt.Errorf("reading handles: %w", err)
	}

	fmt.Printf("═══════════════════════════════════════\n")
	fmt.Printf("  TPM Persistent Key Inventory\n")
	fmt.Printf("  Path:  %s\n", tpmPath)
	fmt.Printf("  Total: %d key(s) found\n", len(handles.Handle))
	fmt.Printf("═══════════════════════════════════════\n\n")

	if len(handles.Handle) == 0 {
		fmt.Println("TPM is clean — no persistent keys.")
		return nil
	}

	for _, handle := range handles.Handle {
		inspectHandle(t, handle)
	}
	return nil
}

// inspectHandle prints everything publicly readable about a single key handle.
// SAFETY: ReadPublic is read-only. The private key is unreachable by design.
func inspectHandle(t transport.TPM, handle tpm2.TPMHandle) {

	fmt.Printf("┌─ Handle: 0x%08X  (%s)\n", uint32(handle), guessHandlePurpose(uint32(handle)))

	pubRsp, err := tpm2.ReadPublic{ObjectHandle: handle}.Execute(t)
	if err != nil {
		fmt.Printf("│  ERROR: %v\n└─\n\n", err)
		return
	}

	pub, err := pubRsp.OutPublic.Contents()
	if err != nil {
		fmt.Printf("│  ERROR unwrapping: %v\n└─\n\n", err)
		return
	}

	fmt.Printf("│\n│  ── Algorithm ──────────────────────────────\n")
	fmt.Printf("│  Name algorithm : %s\n", algName(pub.NameAlg))

	switch pub.Type {
	case tpm2.TPMAlgECC:
		params, err := pub.Parameters.ECCDetail()
		if err != nil {
			fmt.Println("│  Type: ECC (cannot read params)")
			break
		}
		fmt.Printf("│  Key type       : ECC\n")
		fmt.Printf("│  Curve          : %s\n", curveName(params.CurveID))
		fmt.Printf("│  Signing scheme : %s\n", schemeName(params.Scheme.Scheme))
		fmt.Printf("│  KDF scheme     : %s\n", algName(params.KDF.Scheme))
		if unique, err := pub.Unique.ECC(); err == nil {
			fmt.Printf("│  Public key X   : %s\n", hex.EncodeToString(unique.X.Buffer))
			fmt.Printf("│  Public key Y   : %s\n", hex.EncodeToString(unique.Y.Buffer))
		}

	case tpm2.TPMAlgRSA:
		params, err := pub.Parameters.RSADetail()
		if err != nil {
			fmt.Println("│  Type: RSA (cannot read params)")
			break
		}
		exp := params.Exponent
		if exp == 0 {
			exp = 65537
		}
		fmt.Printf("│  Key type       : RSA\n")
		fmt.Printf("│  Key size       : %d bits\n", params.KeyBits)
		fmt.Printf("│  Signing scheme : %s\n", schemeName(params.Scheme.Scheme))
		fmt.Printf("│  Exponent       : %d\n", exp)
		if unique, err := pub.Unique.RSA(); err == nil {
			fmt.Printf("│  Modulus (hex)  : %s...\n", hex.EncodeToString(unique.Buffer[:16]))
			fmt.Printf("│  Modulus length : %d bytes (%d bits)\n", len(unique.Buffer), len(unique.Buffer)*8)
		}

	default:
		fmt.Printf("│  Key type       : unknown (0x%04X)\n", uint16(pub.Type))
	}

	fmt.Printf("│\n│  ── Authorization ──────────────────────────\n")
	if len(pub.AuthPolicy.Buffer) > 0 {
		fmt.Printf("│  Auth policy    : %s\n", hex.EncodeToString(pub.AuthPolicy.Buffer))
	} else {
		fmt.Printf("│  Auth policy    : none\n")
	}

	a := pub.ObjectAttributes
	fmt.Printf("│\n│  ── Attributes ─────────────────────────────\n")
	fmt.Printf("│  FixedTPM        : %v  ← hardware-bound, cannot be exported\n", a.FixedTPM)
	fmt.Printf("│  FixedParent     : %v\n", a.FixedParent)
	fmt.Printf("│  TPM-generated   : %v  ← created inside the chip\n", a.SensitiveDataOrigin)
	fmt.Printf("│  UserWithAuth    : %v\n", a.UserWithAuth)
	fmt.Printf("│  AdminWithPolicy : %v\n", a.AdminWithPolicy)
	fmt.Printf("│  NoDA            : %v\n", a.NoDA)
	fmt.Printf("│  Restricted      : %v  ← true = platform/manufacturer key\n", a.Restricted)
	fmt.Printf("│  SignEncrypt     : %v\n", a.SignEncrypt)
	fmt.Printf("│  Decrypt         : %v\n", a.Decrypt)
	fmt.Printf("│  STClear         : %v\n", a.STClear)

	fmt.Printf("│\n│  ── Identity ───────────────────────────────\n")
	fmt.Printf("│  TPM Name        : %s\n", hex.EncodeToString(pubRsp.Name.Buffer))
	fmt.Printf("└─────────────────────────────────────────\n\n")
}

func guessHandlePurpose(h uint32) string {
	switch {
	case h == 0x81000001:
		return "OUR application key"
	case h >= 0x81000000 && h <= 0x8100FFFF:
		return "Owner/application range"
	case h == 0x81010001:
		return "commonly: Endorsement Key (EK) RSA"
	case h == 0x81010002:
		return "commonly: Endorsement Key (EK) ECC"
	case h >= 0x81010000 && h <= 0x8101FFFF:
		return "Endorsement/platform range"
	case h >= 0x81020000 && h <= 0x8102FFFF:
		return "Platform range"
	default:
		return "persistent range"
	}
}

func algName(alg tpm2.TPMAlgID) string {
	switch alg {
	case tpm2.TPMAlgSHA256:
		return "SHA-256"
	case tpm2.TPMAlgSHA384:
		return "SHA-384"
	case tpm2.TPMAlgSHA512:
		return "SHA-512"
	case tpm2.TPMAlgSHA1:
		return "SHA-1"
	case tpm2.TPMAlgNull:
		return "null"
	default:
		return fmt.Sprintf("0x%04X", uint16(alg))
	}
}

func curveName(curve tpm2.TPMECCCurve) string {
	switch curve {
	case tpm2.TPMECCNistP256:
		return "P-256 (NIST)"
	case tpm2.TPMECCNistP384:
		return "P-384 (NIST)"
	case tpm2.TPMECCNistP521:
		return "P-521 (NIST)"
	default:
		return fmt.Sprintf("unknown (0x%04X)", uint16(curve))
	}
}

func schemeName(scheme tpm2.TPMAlgID) string {
	switch scheme {
	case tpm2.TPMAlgECDSA:
		return "ECDSA"
	case tpm2.TPMAlgECDAA:
		return "ECDAA"
	case tpm2.TPMAlgRSASSA:
		return "RSASSA (PKCS#1 v1.5)"
	case tpm2.TPMAlgRSAPSS:
		return "RSAPSS"
	case tpm2.TPMAlgOAEP:
		return "OAEP (encryption)"
	case tpm2.TPMAlgNull:
		return "null (parent/storage key)"
	default:
		return fmt.Sprintf("unknown (0x%04X)", uint16(scheme))
	}
}
