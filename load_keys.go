package envenc

import (
	"errors"
)

// LoadKeysFromFile reads and decrypts keys from an encrypted vault file.
// It returns the decrypted key/value map or an error if the file does not
// exist, cannot be read, or decryption fails.
func LoadKeysFromFile(vaultFilePath, vaultPassword string) (map[string]string, error) {
	if !fileExists(vaultFilePath) {
		return nil, errors.New("Vault file not found: " + vaultFilePath)
	}
	keys, err := KeyListFromFile(vaultFilePath, vaultPassword)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// LoadKeysFromString decrypts keys from the provided encrypted vault content
// string and returns the resulting key/value map.
func LoadKeysFromString(vaultContent, vaultPassword string) (map[string]string, error) {
	keys, err := KeyListFromString(vaultContent, vaultPassword)
	if err != nil {
		return nil, err
	}
	return keys, nil
}
