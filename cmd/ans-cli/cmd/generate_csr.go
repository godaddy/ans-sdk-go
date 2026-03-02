package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func buildGenerateCSRCmd() *cobra.Command {
	var (
		csrHost    string
		csrOrg     string
		csrCountry string
		csrVersion string
		csrOutDir  string
		csrKeySize int
	)

	cmd := &cobra.Command{
		Use:   "generate-csr",
		Short: "Generate identity and server CSRs",
		Long: `Generate RSA key pairs and Certificate Signing Requests (CSRs) for both
identity and server certificates. The CSRs are base64-encoded PEM format ready
for use in agent registration.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runGenerateCSRWithParams(csrHost, csrOrg, csrCountry, csrVersion, csrOutDir, csrKeySize)
		},
	}

	cmd.Flags().StringVar(&csrHost, "host", "", "Agent host domain (required)")
	cmd.Flags().StringVar(&csrOrg, "org", "", "Organization name (required)")
	cmd.Flags().StringVar(&csrVersion, "version", "", "Agent version for ANS URI (required, e.g., 1.0.0)")
	cmd.Flags().StringVar(&csrCountry, "country", "US", "Country code (default: US)")
	cmd.Flags().StringVar(&csrOutDir, "out-dir", ".", "Output directory for keys and CSRs (default: current directory)")
	cmd.Flags().IntVar(&csrKeySize, "key-size", DefaultRSAKeySize, "RSA key size in bits (default: 2048)")

	_ = cmd.MarkFlagRequired("host")
	_ = cmd.MarkFlagRequired("org")
	_ = cmd.MarkFlagRequired("version")

	return cmd
}

func runGenerateCSRWithParams(host, org, country, version, outDir string, keySize int) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Generating CSRs for host: %s\n", host)
	fmt.Fprintf(os.Stdout, "Organization: %s\n", org)
	fmt.Fprintf(os.Stdout, "Version: %s\n", version)
	fmt.Fprintf(os.Stdout, "Country: %s\n", country)
	fmt.Fprintf(os.Stdout, "Key size: %d bits\n\n", keySize)

	// Generate ANS URI
	ansURI := fmt.Sprintf("ans://v%s.%s", version, host)

	// Generate identity certificate CSR
	fmt.Fprintln(os.Stdout, "Generating identity certificate...")
	if err := generateCSR("identity", host, org, country, ansURI, keySize, outDir); err != nil {
		return fmt.Errorf("failed to generate identity CSR: %w", err)
	}

	// Generate server certificate CSR
	fmt.Fprintln(os.Stdout, "Generating server certificate...")
	if err := generateCSR("server", host, org, country, ansURI, keySize, outDir); err != nil {
		return fmt.Errorf("failed to generate server CSR: %w", err)
	}

	fmt.Fprintf(os.Stdout, "\n✓ CSRs generated successfully in: %s\n", outDir)
	fmt.Fprintln(os.Stdout, "\nFiles created:")
	fmt.Fprintf(os.Stdout, "  - identity.key (private key)\n")
	fmt.Fprintf(os.Stdout, "  - identity.csr (CSR for identity certificate)\n")
	fmt.Fprintf(os.Stdout, "  - server.key (private key)\n")
	fmt.Fprintf(os.Stdout, "  - server.csr (CSR for server certificate)\n")
	fmt.Fprintln(os.Stdout, "\nNext steps:")
	fmt.Fprintf(os.Stdout, "  Register your agent using:\n")
	fmt.Fprintf(os.Stdout, "  ans-cli register --name \"My Agent\" --host %s --version 1.0.0 \\\n", host)
	fmt.Fprintf(os.Stdout, "    --identity-csr %s/identity.csr --server-csr %s/server.csr \\\n", outDir, outDir)
	fmt.Fprintf(os.Stdout, "    --endpoint-url https://%s/api --endpoint-protocol MCP\n", host)

	return nil
}

func generateCSR(name, host, org, country, ansURI string, keySize int, outDir string) error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Parse ANS URI
	uri, err := url.Parse(ansURI)
	if err != nil {
		return fmt.Errorf("failed to parse ANS URI: %w", err)
	}

	// Create CSR template with both DNS and URI SANs
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{org},
			Country:      []string{country},
		},
		DNSNames: []string{host},
		URIs:     []*url.URL{uri},
	}

	// Create CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	// Write private key to file
	keyPath := filepath.Join(outDir, fmt.Sprintf("%s.key", name))
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer func() {
		if closeErr := keyFile.Close(); closeErr != nil {
			err = closeErr
		}
	}()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if encodeErr := pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}); encodeErr != nil {
		return fmt.Errorf("failed to write private key: %w", encodeErr)
	}

	// Write CSR to file
	csrPath := filepath.Join(outDir, fmt.Sprintf("%s.csr", name))
	csrFile, err := os.OpenFile(csrPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create CSR file: %w", err)
	}
	defer func() {
		if closeErr := csrFile.Close(); closeErr != nil {
			err = closeErr
		}
	}()

	if encodeErr := pem.Encode(csrFile, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}); encodeErr != nil {
		return fmt.Errorf("failed to write CSR: %w", encodeErr)
	}

	fmt.Fprintf(os.Stdout, "  ✓ %s.key\n", name)
	fmt.Fprintf(os.Stdout, "  ✓ %s.csr\n", name)

	return nil
}
