package envenc

import (
	"testing"
)

func TestLoadKeysFromFile_LoadsKeys(t *testing.T) {
	seed := map[string]string{
		"API_KEY": "secret123",
		"DB_HOST": "localhost",
	}
	vaultPath, vaultPassword, cleanup := createVaultWithKeys(t, seed)
	defer cleanup()

	keys, err := LoadKeysFromFile(vaultPath, vaultPassword)
	if err != nil {
		t.Fatalf("LoadKeysFromFile failed: %v", err)
	}

	for k, v := range seed {
		if got, ok := keys[k]; !ok {
			t.Errorf("key %s not found in loaded keys", k)
		} else if got != v {
			t.Errorf("key %s mismatch: want %q, got %q", k, v, got)
		}
	}
}

func TestLoadKeysFromFile_FileNotFound(t *testing.T) {
	_, err := LoadKeysFromFile("/does/not/exist/test.vault", "password")
	if err == nil {
		t.Fatal("expected error for non-existent vault file, got nil")
	}
}

func TestLoadKeysFromFile_InvalidPassword(t *testing.T) {
	seed := map[string]string{"K": "V"}
	vaultPath, _, cleanup := createVaultWithKeys(t, seed)
	defer cleanup()

	_, err := LoadKeysFromFile(vaultPath, "wrongpassword")
	if err == nil {
		t.Error("expected error with invalid password")
	}
}

func TestLoadKeysFromString_LoadsKeys(t *testing.T) {
	seed := map[string]string{
		"TOKEN": "abc",
		"URL":   "https://example.com",
	}
	vaultPath, vaultPassword, cleanup := createVaultWithKeys(t, seed)
	defer cleanup()

	vaultString, err := fileGetContents(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault file: %v", err)
	}

	keys, err := LoadKeysFromString(vaultString, vaultPassword)
	if err != nil {
		t.Fatalf("LoadKeysFromString failed: %v", err)
	}

	for k, v := range seed {
		if got, ok := keys[k]; !ok {
			t.Errorf("key %s not found in loaded keys", k)
		} else if got != v {
			t.Errorf("key %s mismatch: want %q, got %q", k, v, got)
		}
	}
}

func TestLoadKeysFromString_InvalidPassword(t *testing.T) {
	seed := map[string]string{"K": "V"}
	vaultPath, _, cleanup := createVaultWithKeys(t, seed)
	defer cleanup()

	vaultString, err := fileGetContents(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault file: %v", err)
	}

	_, err = LoadKeysFromString(vaultString, "wrongpassword")
	if err == nil {
		t.Error("expected error with invalid password")
	}
}

func TestLoadKeysFromString_InvalidContent(t *testing.T) {
	_, err := LoadKeysFromString("invalid encrypted content", "password")
	if err == nil {
		t.Error("expected error for invalid vault content")
	}
}
