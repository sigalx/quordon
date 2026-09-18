package auth

import (
	"errors"
	"testing"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/secrets"
	"golang.org/x/crypto/bcrypt"
)

func TestBasicAuthentication(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), minSupportedBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, problems := NewBasic(config.BasicAuth{
		Realm: "quordon",
		Users: map[string]config.BasicUser{
			"client": {Principal: "principal", PasswordHashSecretRef: "env:HASH"},
		},
	}, secrets.Map{"env:HASH": string(hash)})
	if len(problems) != 0 || !authenticator.Ready() {
		t.Fatalf("problems = %v, ready = %v", problems, authenticator.Ready())
	}
	principal, err := authenticator.Authenticate("client", "correct-password")
	if err != nil || principal.Name != "principal" || principal.ClientIdentifier != "client" {
		t.Fatalf("principal = %#v, error = %v", principal, err)
	}
	if _, err := authenticator.Authenticate("unknown", "correct-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown-user error = %v", err)
	}
}

func TestBasicRejectsNonCanonicalBcryptEncoding(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("password"), minSupportedBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	invalidSalt := append([]byte(nil), hash...)
	invalidSalt[7] = '!'
	nonCanonicalSalt := append([]byte(nil), hash...)
	nonCanonicalSalt[28] = 'A'
	nonCanonicalChecksum := append([]byte(nil), hash...)
	nonCanonicalChecksum[59] = 'A'
	tests := []struct {
		name string
		hash string
	}{
		{name: "trailing byte", hash: string(hash) + "x"},
		{name: "invalid salt alphabet", hash: string(invalidSalt)},
		{name: "non-canonical salt padding bits", hash: string(nonCanonicalSalt)},
		{name: "non-canonical checksum padding bits", hash: string(nonCanonicalChecksum)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authenticator, problems := NewBasic(config.BasicAuth{Users: map[string]config.BasicUser{
				"client": {Principal: "principal", PasswordHash: test.hash},
			}}, secrets.Map{})
			if len(problems) == 0 || authenticator.Ready() {
				t.Fatalf("problems = %v, ready = %v", problems, authenticator.Ready())
			}
		})
	}
}

func TestBasicAuthenticationWithInlineHash(t *testing.T) {
	generated, err := bcrypt.GenerateFromPassword([]byte("inline-password"), minSupportedBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, minor := range []byte{'a', 'b', 'y'} {
		t.Run("2"+string(minor), func(t *testing.T) {
			hash := append([]byte(nil), generated...)
			hash[2] = minor
			authenticator, problems := NewBasic(config.BasicAuth{
				Realm: "quordon",
				Users: map[string]config.BasicUser{
					"inline-client": {Principal: "inline-principal", PasswordHash: string(hash)},
				},
			}, secrets.Map{})
			if len(problems) != 0 || !authenticator.Ready() {
				t.Fatalf("problems = %v, ready = %v", problems, authenticator.Ready())
			}
			principal, err := authenticator.Authenticate("inline-client", "inline-password")
			if err != nil || principal.Name != "inline-principal" || principal.ClientIdentifier != "inline-client" {
				t.Fatalf("principal = %#v, error = %v", principal, err)
			}
		})
	}
}

func TestBasicRejectsMixedBcryptCosts(t *testing.T) {
	first, _ := bcrypt.GenerateFromPassword([]byte("first"), minSupportedBcryptCost)
	second, _ := bcrypt.GenerateFromPassword([]byte("second"), minSupportedBcryptCost+1)
	authenticator, problems := NewBasic(config.BasicAuth{Users: map[string]config.BasicUser{
		"first":  {Principal: "first", PasswordHashSecretRef: "env:FIRST"},
		"second": {Principal: "second", PasswordHashSecretRef: "env:SECOND"},
	}}, secrets.Map{"env:FIRST": string(first), "env:SECOND": string(second)})
	if len(problems) == 0 || authenticator.Ready() {
		t.Fatalf("problems = %v, ready = %v", problems, authenticator.Ready())
	}
}

func TestBasicRejectsExcessiveBcryptCostBeforeDummyHashGeneration(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("password"), minSupportedBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	hash[4] = '3'
	hash[5] = '1'

	authenticator, problems := NewBasic(config.BasicAuth{Users: map[string]config.BasicUser{
		"client": {Principal: "principal", PasswordHash: string(hash)},
	}}, secrets.Map{})
	if len(problems) == 0 || authenticator.Ready() {
		t.Fatalf("problems = %v, ready = %v", problems, authenticator.Ready())
	}
}
