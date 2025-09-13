package envenc

import (
	"github.com/dracory/crypto"
)

const obf = "YT@6toe#e0hIx7pMHyBcU^YsAucNI2Jm2OF6nNjjXR$2qHf&&dqBj6USPhX71*M1W^dpC0DwF1kRm$ntGqe$GuvH$H#7sCWsDD"

// Obfuscate obfuscates an ASCII string (not-compatible with Unicode)
//
// Parameters:
//   - input: string to obfuscate
//
// Returns:
//   - string: obfuscated string
//   - error: error if any
func Obfuscate(input string) (string, error) {
	output1 := crypto.XorFortifiedEncrypt(input, obf)

	output2, err := crypto.AESFortifiedEncrypt(output1, obf)

	if err != nil {
		return "", err
	}

	return output2, nil
}

// Deobfuscate deobfuscates an ASCII string (not-compatible with Unicode)
//
// Parameters:
//   - input: string to deobfuscate
//
// Returns:
//   - string: deobfuscated string
//   - error: error if any
func Deobfuscate(input string) (string, error) {
	output1, err := crypto.AESFortifiedDecrypt(input, obf)

	if err != nil {
		return "", err
	}

	output2, err := crypto.XorFortifiedDecrypt(output1, obf)
	return output2, err
}
