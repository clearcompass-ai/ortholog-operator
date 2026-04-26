// PEM-encoded ECDSA key loader.
//
// Expects a single PEM block of type "EC PRIVATE KEY" (SEC1) or
// "PRIVATE KEY" (PKCS#8). Either format carries an *ecdsa.PrivateKey
// after parsing. P-256 is the recommended curve; the loader accepts
// any stdlib-supported curve.
package signing

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadECDSAFromPEM reads a PEM-encoded ECDSA private key from disk and
// constructs an ECDSASigner bound to the given signerDID.
//
// The file must contain a single PEM block of type:
//   - "EC PRIVATE KEY" (SEC1 format, openssl ecparam output)
//   - "PRIVATE KEY"    (PKCS#8 format, openssl genpkey output)
//
// File permissions are not checked here; production deployments should
// enforce mode 0600 via systemd unit or Kubernetes secret projection.
func LoadECDSAFromPEM(path, signerDID string) (*ECDSASigner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signing: read key file %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signing: no PEM block in %q", path)
	}

	key, err := parseECDSAFromPEMBlock(block)
	if err != nil {
		return nil, fmt.Errorf("signing: parse key from %q: %w", path, err)
	}

	return NewECDSASigner(key, signerDID)
}

func parseECDSAFromPEMBlock(block *pem.Block) (*ecdsa.PrivateKey, error) {
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS#8 parse: %w", err)
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not ECDSA (got %T)", k)
		}
		return ec, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q (want EC PRIVATE KEY or PRIVATE KEY)", block.Type)
	}
}
