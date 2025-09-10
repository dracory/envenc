package envenc

import (
	"os"
	"path/filepath"
	"testing"
)

// createVaultWithKeys creates a temporary vault, optionally seeds it with keys,
// and returns (vaultPath, vaultPassword, cleanupFn).
func createVaultWithKeys(t *testing.T, keys map[string]string) (string, string, func()) {
	t.Helper()
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test.vault")
	vaultPassword := "testpassword"

	if err := Init(vaultPath, vaultPassword); err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	for k, v := range keys {
		if err := KeySet(vaultPath, vaultPassword, k, v); err != nil {
			t.Fatalf("failed to seed key %s: %v", k, err)
		}
	}

	cleanup := func() {
		_ = os.RemoveAll(tempDir)
	}

	return vaultPath, vaultPassword, cleanup
}

func TestHydrateEnvFromFile_SetsEnvironment(t *testing.T) {
	seed := map[string]string{
		"APP_TOKEN":  "abc123",
		"DB_HOST":    "localhost",
		"DB_PORT":    "5432",
	}
	vaultPath, vaultPassword, cleanup := createVaultWithKeys(t, seed)
	defer cleanup()

	// Ensure a clean env and auto-restore after test
	for k := range seed {
		t.Setenv(k, "")
	}

	if err := HydrateEnvFromFile(vaultPath, vaultPassword); err != nil {
		t.Fatalf("HydrateEnvFromFile failed: %v", err)
	}

	for k, v := range seed {
		if got := os.Getenv(k); got != v {
			t.Errorf("env %s mismatch: want %q, got %q", k, v, got)
		}
	}
}

func TestHydrateEnvFromFile_InvalidPath(t *testing.T) {
	// Ensure function validates path and returns an error
	err := HydrateEnvFromFile("/does/not/exist/test.vault", "password")
	if err == nil {
		t.Fatal("expected error for invalid vault path, got nil")
	}
}

func TestHydrateEnvFromString_SetsEnvironment(t *testing.T) {
	seed := map[string]string{
		"SERVICE_URL": "https://example.com",
		"API_KEY":     "xyz",
	}
	vaultPath, vaultPassword, cleanup := createVaultWithKeys(t, seed)
	defer cleanup()

	// Read encrypted vault content as string
	vaultString, err := fileGetContents(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault file: %v", err)
	}

	for k := range seed {
		t.Setenv(k, "")
	}

	if err := HydrateEnvFromString(vaultString, vaultPassword); err != nil {
		t.Fatalf("HydrateEnvFromString failed: %v", err)
	}

	for k, v := range seed {
		if got := os.Getenv(k); got != v {
			t.Errorf("env %s mismatch: want %q, got %q", k, v, got)
		}
	}
}

func TestHydrateEnvFromString_EmptyInputs(t *testing.T) {
	if err := HydrateEnvFromString("", "somepass"); err == nil {
		t.Error("expected error for empty vault content")
	}
	if err := HydrateEnvFromString("somecontent", ""); err == nil {
		t.Error("expected error for empty password")
	}
}

func TestHydrateEnvFromString_InvalidPassword(t *testing.T) {
	seed := map[string]string{"K": "V"}
	vaultPath, vaultPassword, cleanup := createVaultWithKeys(t, seed)
	_ = vaultPassword // ensure we used the correct one for creation
	defer cleanup()

	vaultString, err := fileGetContents(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault file: %v", err)
	}

	if err := HydrateEnvFromString(vaultString, "wrongpassword"); err == nil {
		t.Error("expected error with invalid password")
	}
}
