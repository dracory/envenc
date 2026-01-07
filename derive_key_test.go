package envenc

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	plainPublicKey := "PUBLIC_KEY_WITH_LENGTH_32_CHARS_"
	if len(plainPublicKey) < 32 {
		t.Fatalf("test public key must be at least 32 characters, got %d", len(plainPublicKey))
	}

	privateKey := "PRIVATE_KEY_WITH_LENGTH_32_CHARS"
	if len(privateKey) < 32 {
		t.Fatalf("test private key must be at least 32 characters, got %d", len(privateKey))
	}

	obfuscatedPublicKey, err := Obfuscate(plainPublicKey)
	if err != nil {
		t.Fatalf("failed to obfuscate public key: %v", err)
	}

	expected := func() string {
		sum := sha256.Sum256([]byte(plainPublicKey + privateKey))
		return fmt.Sprintf("%x", sum)
	}()

	tests := []struct {
		name       string
		publicKey  string
		privateKey string
		want       string
		wantErr    string
	}{
		{
			name:       "success returns derived key",
			publicKey:  obfuscatedPublicKey,
			privateKey: privateKey,
			want:       expected,
		},
		{
			name:       "error when public key empty",
			publicKey:  "",
			privateKey: privateKey,
			wantErr:    "envenc public key is empty",
		},
		{
			name:       "error when private key empty",
			publicKey:  obfuscatedPublicKey,
			privateKey: "",
			wantErr:    "envenc private key is empty",
		},
		{
			name:       "error when public key short",
			publicKey:  "short",
			privateKey: privateKey,
			wantErr:    "envenc public key is too short",
		},
		{
			name:       "error when private key short",
			publicKey:  obfuscatedPublicKey,
			privateKey: "short",
			wantErr:    "envenc private key is too short",
		},
		{
			name:       "error when public key not obfuscated",
			publicKey:  strings.Repeat("A", 32),
			privateKey: privateKey,
			wantErr:    "failed to deobfuscate public key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeriveKey(tc.publicKey, tc.privateKey)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error to contain %q, got %v", tc.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("expected key %q, got %q", tc.want, got)
			}
		})
	}
}
