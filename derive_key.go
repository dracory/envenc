package envenc

import (
	"crypto/sha256"
	"fmt"
)

// DeriveKey: Derives the final envenc encryption key from a public and private key pair.
//
// This is an optional helper function intended for end users. It is not required
// for the internal functioning of this package.
//
// This function generates the final encryption key used for securing an envenc vault file.
// It combines a private key with a public key, performs a secure hashing
// operation, and returns the resulting hash as the encryption key.
//
// Business Logic:
//  1. Public Key Retrieval and Deobfuscation:
//     - The function receives the public key.
//     - It then deobfuscates the public key using the envenc.Deobfuscate function.
//     This step adds a layer of security against reverse engineering.
//  2. Temporary Key Generation:
//     - The function concatenates the public key with the private key.
//     - Key Concatenation Order: The order of concatenation (public key + private key)
//     is vital and MUST be consistent across all key generation and validation processes.
//
// 3. Secure Hashing:
//   - The function calculates the SHA256 hash of the temporary key.
//   - SHA256 is a robust one-way hashing algorithm. This ensures that the original keys cannot
//     be recovered from the generated hash, providing strong cryptographic security.
//
// 4. Final Key Formatting:
//   - The resulting hash (a byte array) is converted into a hexadecimal string representation.
//
// 5. Key Return:
//   - The function returns the hexadecimal string, which is the final encryption key.
//
// Parameters:
// - envencPublicKey (string): The public key used in the encryption key derivation.
// This key is expected to be obfuscated.
// - envencPrivateKey (string): The private key used in the encryption key derivation.
// This key MUST be kept strictly confidential and handled with extreme care.
//
// Returns:
// - string: The final envenc encryption key as a hexadecimal string.
// - error: Returns an error if the public key deobfuscation fails.
//
// Security Considerations:
// - Private Key Protection: The `envencPrivateKey` is the most sensitive piece of information.
// It should never be stored in plain text or committed to version control. Use secure environment
// variables or configuration management systems.
// - Public Key Obfuscation: The public key is deobfuscated to prevent it from being easily
// extracted from compiled applications. While not as sensitive as the private key, obfuscation
// adds an extra layer of security.
// - One-Way Hashing: The use of SHA256 ensures that the key derivation process is one-way.
// It is computationally infeasible to derive the original private and public keys from the
// generated hash.
// - Key Generation Dynamics: The final encryption key is generated dynamically each time it is
// needed. It should not be stored persistently.
// - CSPRNG: Ensure the private and public keys are generated using a cryptographically secure
// pseudorandom number generator (CSPRNG).
// - Zeroize tempKey: The tempKey variable should be overwritten as soon as the hash is generated.
//
// Example:
// publicKey := "your_public_key"
// privateKey := "your_private_key"
// finalKey, err := DeriveKey(publicKey, privateKey)
// if err != nil {
// // Handle error
// }
// // Use finalKey for encryption
func DeriveKey(envencPublicKey string, envencPrivateKey string) (string, error) {
	if envencPublicKey == "" {
		return "", fmt.Errorf("envenc public key is empty")
	}

	if envencPrivateKey == "" {
		return "", fmt.Errorf("envenc private key is empty")
	}

	if len(envencPublicKey) < 32 {
		return "", fmt.Errorf("envenc public key is too short (should be at least 32 characters)")
	}

	if len(envencPrivateKey) < 32 {
		return "", fmt.Errorf("envenc private key is too short (should be at least 32 characters)")
	}

	publicKey, err := Deobfuscate(envencPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to deobfuscate public key: %w", err)
	}

	tempKey := publicKey + envencPrivateKey

	hash := sha256.Sum256([]byte(tempKey))
	realKey := fmt.Sprintf("%x", hash)
	tempKey = "" //Zeroize tempKey

	return realKey, nil
}
