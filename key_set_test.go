package envenc_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dracory/envenc"
)

func setupTestVault(t *testing.T) (string, string) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test.vault")
	vaultPassword := "testpassword"

	// Create an empty vault file
	if err := envenc.Init(vaultPath, vaultPassword); err != nil {
		t.Fatalf("Failed to create vault file: %v", err)
	}

	return vaultPath, vaultPassword
}

func TestKeySet_NewKey(t *testing.T) {
	vaultPath, vaultPassword := setupTestVault(t)
	keyName := "testkey"
	keyValue := "testvalue"

	err := envenc.KeySet(vaultPath, vaultPassword, keyName, keyValue)
	if err != nil {
		t.Errorf("KeySet failed to set new key: %v", err)
	}

	// Clean up
	os.Remove(vaultPath)
}

func TestKeySet_UpdateKey(t *testing.T) {
	vaultPath, vaultPassword := setupTestVault(t)
	keyName := "testkey"
	keyValue := "testvalue"

	// First set the key
	err := envenc.KeySet(vaultPath, vaultPassword, keyName, keyValue)
	if err != nil {
		t.Errorf("KeySet failed to set initial key: %v", err)
		return
	}

	// Then update it
	newKeyValue := "updatedvalue"
	err = envenc.KeySet(vaultPath, vaultPassword, keyName, newKeyValue)
	if err != nil {
		t.Errorf("KeySet failed to update existing key: %v", err)
	}

	// Clean up
	os.Remove(vaultPath)
}

func TestKeySet_InvalidPassword(t *testing.T) {
	vaultPath, vaultPassword := setupTestVault(t)
	keyName := "testkey"
	keyValue := "testvalue"

	// First set the key with correct password
	err := envenc.KeySet(vaultPath, vaultPassword, keyName, keyValue)
	if err != nil {
		t.Errorf("KeySet failed to set initial key: %v", err)
		return
	}

	// Then try to update with invalid password
	invalidPassword := "wrongpassword"
	err = envenc.KeySet(vaultPath, invalidPassword, keyName, keyValue)
	if err == nil {
		t.Error("KeySet should have failed with invalid password")
	}

	// Clean up
	os.Remove(vaultPath)
}

func TestKeySet_InvalidFilePath(t *testing.T) {
	vaultPath, vaultPassword := setupTestVault(t)
	keyName := "testkey"
	keyValue := "testvalue"

	// Create a non-existent directory path
	invalidPath := filepath.Join(vaultPath, "nonexistent", "test.vault")
	err := envenc.KeySet(invalidPath, vaultPassword, keyName, keyValue)
	if err == nil {
		t.Error("KeySet should have failed with invalid file path")
	}

	// Clean up
	os.Remove(vaultPath)
}
