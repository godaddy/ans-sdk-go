// Package keygen provides cryptographic utilities for ANS agent key generation and management.
package keygen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// Minimum and default key sizes for RSA keys.
const (
	MinRSAKeySize     = 2048
	DefaultRSAKeySize = 2048
)

// CurveP256 returns the P-256 (secp256r1) elliptic curve.
func CurveP256() elliptic.Curve { return elliptic.P256() }

// CurveP384 returns the P-384 (secp384r1) elliptic curve.
func CurveP384() elliptic.Curve { return elliptic.P384() }

// CurveP521 returns the P-521 (secp521r1) elliptic curve.
func CurveP521() elliptic.Curve { return elliptic.P521() }

// GenerateRSAKeyPair generates a new RSA key pair with the specified bit size.
// The minimum allowed key size is 2048 bits.
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	if bits < MinRSAKeySize {
		return nil, fmt.Errorf("RSA key size must be at least %d bits, got %d", MinRSAKeySize, bits)
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// GenerateECKeyPair generates a new ECDSA key pair for the specified curve.
// Supported curves: P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1).
func GenerateECKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	if curve == nil {
		return nil, errors.New("curve cannot be nil")
	}
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// PrivateKeyToPEM converts a private key to PEM format.
// Supports RSA and ECDSA keys. If password is non-nil and non-empty,
// the key will be encrypted using AES-256-CBC.
func PrivateKeyToPEM(key crypto.PrivateKey, password []byte) ([]byte, error) {
	var pemBlock *pem.Block

	switch k := key.(type) {
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal EC private key: %w", err)
		}
		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}

	// Encrypt if password provided
	// Note: x509.EncryptPEMBlock is deprecated but still widely used for compatibility
	if len(password) > 0 {
		//nolint:staticcheck // Using deprecated API for PEM encryption compatibility
		encryptedBlock, err := x509.EncryptPEMBlock(
			rand.Reader,
			pemBlock.Type,
			pemBlock.Bytes,
			password,
			x509.PEMCipherAES256,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}
		pemBlock = encryptedBlock
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// PublicKeyToPEM converts a public key to PEM format.
// Supports RSA and ECDSA public keys.
func PublicKeyToPEM(key crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// ParsePrivateKeyPEM parses a PEM-encoded private key.
// Supports RSA and EC private keys, with optional password decryption.
func ParsePrivateKeyPEM(pemData []byte, password []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	var der []byte
	var err error

	// Decrypt if encrypted
	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck // Deprecated but still widely used
		der, err = x509.DecryptPEMBlock(block, password) //nolint:staticcheck // Deprecated but still widely used
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
	} else {
		der = block.Bytes
	}

	// Try RSA first
	if rsaKey, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return rsaKey, nil
	}

	// Try PKCS8 (can contain RSA or EC)
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}

	// Try EC
	if ecKey, err := x509.ParseECPrivateKey(der); err == nil {
		return ecKey, nil
	}

	return nil, errors.New("failed to parse private key: unknown format")
}

// SavePrivateKeyPEM saves a private key to a file in PEM format.
// The file is created with mode 0600 (owner read/write only).
func SavePrivateKeyPEM(key crypto.PrivateKey, path string, password []byte) error {
	pemData, err := PrivateKeyToPEM(key, password)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}

	if _, err := file.Write(pemData); err != nil {
		closeErr := file.Close()
		return errors.Join(fmt.Errorf("failed to write key: %w", err), closeErr)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	return nil
}

// LoadPrivateKeyPEM loads a private key from a PEM file.
func LoadPrivateKeyPEM(path string, password []byte) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return ParsePrivateKeyPEM(data, password)
}

// SavePublicKeyPEM saves a public key to a file in PEM format.
// Public keys use 0644 permissions since they are meant to be shared.
func SavePublicKeyPEM(key crypto.PublicKey, path string) error {
	pemData, err := PublicKeyToPEM(key)
	if err != nil {
		return err
	}

	//nolint:gosec // G302: Public keys are meant to be shared; 0644 allows read access for others
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}

	if _, err := file.Write(pemData); err != nil {
		closeErr := file.Close()
		return errors.Join(fmt.Errorf("failed to write key: %w", err), closeErr)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	return nil
}

// LoadPublicKeyPEM loads a public key from a PEM file.
func LoadPublicKeyPEM(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	return x509.ParsePKIXPublicKey(block.Bytes)
}

// GetPublicKey extracts the public key from a private key.
func GetPublicKey(key crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// KeyPair holds a generated key pair with its PEM representations.
type KeyPair struct {
	PrivateKey    crypto.PrivateKey
	PublicKey     crypto.PublicKey
	PrivateKeyPEM []byte
	PublicKeyPEM  []byte
}

// GenerateRSAKeyPairWithPEM generates an RSA key pair and returns both keys with PEM encoding.
func GenerateRSAKeyPairWithPEM(bits int, password []byte) (*KeyPair, error) {
	privateKey, err := GenerateRSAKeyPair(bits)
	if err != nil {
		return nil, err
	}

	privateKeyPEM, err := PrivateKeyToPEM(privateKey, password)
	if err != nil {
		return nil, err
	}

	publicKeyPEM, err := PublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		PrivateKeyPEM: privateKeyPEM,
		PublicKeyPEM:  publicKeyPEM,
	}, nil
}

// GenerateECKeyPairWithPEM generates an EC key pair and returns both keys with PEM encoding.
func GenerateECKeyPairWithPEM(curve elliptic.Curve, password []byte) (*KeyPair, error) {
	privateKey, err := GenerateECKeyPair(curve)
	if err != nil {
		return nil, err
	}

	privateKeyPEM, err := PrivateKeyToPEM(privateKey, password)
	if err != nil {
		return nil, err
	}

	publicKeyPEM, err := PublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		PrivateKeyPEM: privateKeyPEM,
		PublicKeyPEM:  publicKeyPEM,
	}, nil
}

// WriteKeyPairToFiles writes a key pair to the specified files.
// The private key PEM is written as-is, preserving any encryption applied during generation.
func (kp *KeyPair) WriteKeyPairToFiles(privateKeyPath, publicKeyPath string) error {
	if err := os.WriteFile(privateKeyPath, kp.PrivateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := SavePublicKeyPEM(kp.PublicKey, publicKeyPath); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	return nil
}

// WritePrivateKeyTo writes the private key PEM to a writer.
func (kp *KeyPair) WritePrivateKeyTo(w io.Writer) (int, error) {
	return w.Write(kp.PrivateKeyPEM)
}

// WritePublicKeyTo writes the public key PEM to a writer.
func (kp *KeyPair) WritePublicKeyTo(w io.Writer) (int, error) {
	return w.Write(kp.PublicKeyPEM)
}
