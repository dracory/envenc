package envenc

import (
	"testing"
)

func TestEncryptDoesNotFail(t *testing.T) {
	// Arrange

	// Act
	enc, err := Encrypt("test", "pass")

	if err != nil {
		t.Fatal(err)
	}

	// Assert
	if enc == "" {
		t.Fatal("Encrypted string is empty")
	}
}

func TestEncryptGeneratesDifferentResults(t *testing.T) {
	// Arrange

	// Act
	enc, err := Encrypt("test", "pass")

	if err != nil {
		t.Fatal(err)
	}

	// Assert
	if enc == "" {
		t.Fatal("Encrypted string is empty")
	}

	// Act
	enc2, err := Encrypt("test", "pass")

	if err != nil {
		t.Fatal(err)
	}

	// Assert
	if enc == enc2 {
		t.Fatal("Encrypted strings are equal")
	}
}

func TestDecryptWorks(t *testing.T) {
	// Arrange
	enc, err := Encrypt("test", "pass")

	if err != nil {
		t.Fatal(err)
	}

	// Act
	dec, err := Decrypt(enc, "pass")

	if err != nil {
		t.Fatal(err)
	}

	// Assert
	if dec == "" {
		t.Fatal("Decrypted string is empty")
	}

	if dec != "test" {
		t.Fatal("Decrypted string is not 'test'", dec)
	}
}

func TestDecryptFailsWithWrongPassword(t *testing.T) {
	// Arrange
	enc, err := Encrypt("test", "pass")

	if err != nil {
		t.Fatal(err)
	}

	// Act
	_, err = Decrypt(enc, "wrong")

	if err == nil {
		t.Fatal("Decryption should have failed")
	}
}
