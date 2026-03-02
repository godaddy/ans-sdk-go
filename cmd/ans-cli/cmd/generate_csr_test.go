package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildGenerateCSRCmd(t *testing.T) {
	cmd := buildGenerateCSRCmd()

	if cmd == nil {
		t.Fatal("buildGenerateCSRCmd() returned nil")
	}

	if cmd.Use != "generate-csr" {
		t.Errorf("Use = %q, want %q", cmd.Use, "generate-csr")
	}

	// Verify flags
	flags := []string{"host", "org", "version", "country", "out-dir", "key-size"}
	for _, flagName := range flags {
		if cmd.Flags().Lookup(flagName) == nil {
			t.Errorf("missing flag %q", flagName)
		}
	}
}

func TestRunGenerateCSRWithParams(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	err := runGenerateCSRWithParams("test.example.com", "TestOrg", "US", "1.0.0", tmpDir, DefaultRSAKeySize)
	if err != nil {
		t.Fatalf("runGenerateCSRWithParams() unexpected error: %v", err)
	}

	// Verify files were created
	expectedFiles := []string{
		"identity.key",
		"identity.csr",
		"server.key",
		"server.csr",
	}

	for _, file := range expectedFiles {
		path := filepath.Join(tmpDir, file)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("expected file %s to exist: %v", file, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("expected file %s to be non-empty", file)
		}
		// Verify key files have restricted permissions
		if filepath.Ext(file) == ".key" {
			perm := info.Mode().Perm()
			if perm&0077 != 0 {
				t.Errorf("key file %s has insecure permissions: %o", file, perm)
			}
		}
	}
}

func TestRunGenerateCSRWithParams_InvalidOutDir(t *testing.T) {
	// Use a path that can't be created (nested under a file)
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "file.txt")

	// Create a file where we need a directory
	if err := os.WriteFile(fakePath, []byte("content"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	err := runGenerateCSRWithParams("test.example.com", "TestOrg", "US", "1.0.0",
		filepath.Join(fakePath, "subdir"), DefaultRSAKeySize)
	if err == nil {
		t.Fatal("expected error for invalid output directory, got nil")
	}
}

func TestRunGenerateCSRWithParams_CreatesNestedDir(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "a", "b", "c")

	err := runGenerateCSRWithParams("test.example.com", "TestOrg", "US", "1.0.0", outDir, 2048)
	if err != nil {
		t.Fatalf("runGenerateCSRWithParams() error = %v", err)
	}

	info, err := os.Stat(outDir)
	if err != nil {
		t.Fatalf("expected output directory to exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected output path to be a directory")
	}
}

func TestGenerateCSR_VerifyOutput(t *testing.T) {
	tmpDir := t.TempDir()

	err := generateCSR("test", "host.example.com", "TestOrg", "US", "ans://v1.0.0.host.example.com", 2048, tmpDir)
	if err != nil {
		t.Fatalf("generateCSR() error = %v", err)
	}

	keyPath := filepath.Join(tmpDir, "test.key")
	csrPath := filepath.Join(tmpDir, "test.csr")

	for _, path := range []string{keyPath, csrPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected file to exist at %s: %v", path, err)
		}
		if info.Size() == 0 {
			t.Errorf("expected file %s to have content", path)
		}
	}

	// Verify key file permissions
	keyInfo, _ := os.Stat(keyPath)
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("key file permissions = %v, want 0600", keyInfo.Mode().Perm())
	}
}

func TestGenerateCSR_InvalidKeyPath(t *testing.T) {
	err := generateCSR("test", "host.example.com", "TestOrg", "US", "ans://v1.0.0.host.example.com", 2048, "/dev/null/nodir")
	if err == nil {
		t.Fatal("expected error for bad output directory")
	}
}
