package main

import (
	"fmt"
	"log"

	"tpm-sidecar/internal/tpm"
)

const (
	tpmDevice = "/dev/tpmrm0"

	// AppKeyHandle is the persistent TPM handle for our application signing key.
	// 0x8100002A = persistent range (0x81000000) + 42 (0x2A).
	// This handle is fixed for the lifetime of the device — never change it
	// after the first provisioning, or the certificate chain will break.
	AppKeyHandle uint32 = 0x8100002A
)

func main() {
	// CreateKey is idempotent:
	//   first run  → generates key, persists it, returns public key
	//   later runs → finds key already exists, returns its public key
	publicKeyPEM, err := tpm.CreateKey(tpmDevice, AppKeyHandle)
	if err != nil {
		log.Fatalf("CreateKey: %v", err)
	}

	fmt.Println("Public key (safe to share — private key never left the TPM):")
	fmt.Println(publicKeyPEM)

	// List all keys to confirm the handle is occupied.
	fmt.Println("Current TPM key inventory:")
	if err := tpm.ListPersistentKeys(tpmDevice); err != nil {
		log.Fatalf("ListPersistentKeys: %v", err)
	}
}
