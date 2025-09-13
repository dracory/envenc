package envenc

import "github.com/dracory/crypto"

func Encrypt(input string, password string) (string, error) {
	xorEncString := crypto.XorFortifiedEncrypt(input, password)

	finalEncString, err := crypto.AESFortifiedEncrypt(xorEncString, password)

	return finalEncString, err
}

func Decrypt(input string, password string) (string, error) {
	aesEncString, err := crypto.AESFortifiedDecrypt(input, password)

	if err != nil {
		return "", err
	}

	return crypto.XorFortifiedDecrypt(aesEncString, password)
}
