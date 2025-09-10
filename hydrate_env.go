package envenc

import (
	"errors"
	"os"
)

// HydrateEnvFromFile decrypts keys from an encrypted vault file at
// vaultFilePath using password, and writes them into the current process
// environment via os.Setenv. Existing variables will be overwritten.
//
// Parameters:
//
//	vaultFilePath: Path to the encrypted vault file
//	vaultPassword: Password to decrypt the vault file
//
// Returns:
//
//	error: If any step fails
func HydrateEnvFromFile(vaultFilePath, vaultPassword string) error {
	if vaultFilePath == "" {
		return errors.New("vault file path is required")
	}

	if vaultPassword == "" {
		return errors.New("vault password is required")
	}

	keys, err := loadKeysFromFile(vaultFilePath, vaultPassword)
	if err != nil {
		return err
	}
	return applyEnv(keys)
}

// HydrateEnvFromString decrypts keys from the provided encrypted vault
// content using password, and writes them into the current process
// environment via os.Setenv. Existing variables will be overwritten.
//
// Parameters:
//
//	vaultContent: Encrypted vault content as string
//	vaultPassword: Password to decrypt the vault content
//
// Returns:
//
//	error: If any step fails
func HydrateEnvFromString(vaultContent, vaultPassword string) error {
	if vaultContent == "" {
		return errors.New("vault content is required")
	}

	if vaultPassword == "" {
		return errors.New("vault password is required")
	}

	keys, err := loadKeysFromString(vaultContent, vaultPassword)
	if err != nil {
		return err
	}

	return applyEnv(keys)
}

// loadKeysFromFile reads and decrypts keys from an encrypted vault file.
// It returns the decrypted key/value map or an error if the file does not
// exist, cannot be read, or decryption fails.
func loadKeysFromFile(vaultFilePath, vaultPassword string) (map[string]string, error) {
	if !fileExists(vaultFilePath) {
		return nil, errors.New("Vault file not found: " + vaultFilePath)
	}
	keys, err := KeyListFromFile(vaultFilePath, vaultPassword)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// loadKeysFromString decrypts keys from the provided encrypted vault content
// string and returns the resulting key/value map.
func loadKeysFromString(vaultContent, vaultPassword string) (map[string]string, error) {
	keys, err := KeyListFromString(vaultContent, vaultPassword)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// applyEnv writes the provided key/value pairs into the process environment.
// Existing variables with the same keys will be overwritten.
func applyEnv(keys map[string]string) error {
	for k, v := range keys {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}
	return nil
}
