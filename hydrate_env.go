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

	keys, err := LoadKeysFromFile(vaultFilePath, vaultPassword)
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

	keys, err := LoadKeysFromString(vaultContent, vaultPassword)
	if err != nil {
		return err
	}

	return applyEnv(keys)
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
