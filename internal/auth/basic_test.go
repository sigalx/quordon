package auth

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
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

func TestBasicAcceptsMixedBcryptCosts(t *testing.T) {
	first, err := bcrypt.GenerateFromPassword([]byte("first"), minSupportedBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	second, err := bcrypt.GenerateFromPassword([]byte("second"), minSupportedBcryptCost+2)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, problems := NewBasic(config.BasicAuth{Users: map[string]config.BasicUser{
		"first.client":  {Principal: "first", PasswordHash: string(first)},
		"second.client": {Principal: "second", PasswordHashSecretRef: "env:SECOND"},
		"shared.client": {Principal: "shared", PasswordHash: string(first)},
	}}, secrets.Map{"env:SECOND": string(second)})
	if len(problems) != 0 || !authenticator.Ready() {
		t.Fatalf("problems = %v, ready = %v", problems, authenticator.Ready())
	}
	for _, test := range []struct {
		username, password, principal string
	}{
		{"first.client", "first", "first"},
		{"second.client", "second", "second"},
		{"shared.client", "first", "shared"},
		{"first.client", "second", ""},
		{"second.client", "first", ""},
		{"unknown.client", "first", ""},
		{"unknown.client", "quordon-dummy-password", ""},
		{"first.client", "quordon-dummy-password", ""},
	} {
		t.Run(test.username+"/"+test.password, func(t *testing.T) {
			principal, err := authenticator.Authenticate(test.username, test.password)
			if test.principal == "" {
				if !errors.Is(err, ErrInvalidCredentials) || principal != (Principal{}) {
					t.Fatalf("invalid credentials returned principal=%#v error=%v", principal, err)
				}
			} else if err != nil || principal.Name != test.principal || principal.ClientIdentifier != test.username {
				t.Fatalf("principal=%#v error=%v", principal, err)
			}
		})
	}

	// Inspect actual comparison calls rather than comparing noisy elapsed times.
	// Success, failure, unknown users and multiple users sharing one cost must
	// all perform the same bounded sequence of expensive operations.
	for _, username := range []string{"first.client", "second.client", "shared.client", "unknown.client"} {
		for _, success := range []bool{false, true} {
			t.Run(fmt.Sprintf("comparison work/%s/%t", username, success), func(t *testing.T) {
				var costs []int
				realComparisons := 0
				principal, err := authenticator.authenticate(username, "attempt", func(hash, password []byte) error {
					cost, err := bcrypt.Cost(hash)
					if err != nil || string(password) != "attempt" {
						t.Fatalf("invalid comparison inputs: cost error=%v", err)
					}
					costs = append(costs, cost)
					if bytes.Equal(hash, first) || bytes.Equal(hash, second) {
						realComparisons++
					}
					if success {
						return nil
					}
					return bcrypt.ErrMismatchedHashAndPassword
				})
				if !slices.Equal(costs, []int{minSupportedBcryptCost, minSupportedBcryptCost + 2}) {
					t.Fatalf("bcrypt comparison costs = %v", costs)
				}
				if username == "unknown.client" {
					if realComparisons != 0 || !errors.Is(err, ErrInvalidCredentials) || principal != (Principal{}) {
						t.Fatalf("unknown user: real checks=%d principal=%#v error=%v", realComparisons, principal, err)
					}
				} else if realComparisons != 1 || success != (err == nil) {
					t.Fatalf("known user: real checks=%d error=%v", realComparisons, err)
				}
			})
		}
	}
}

func TestBasicRejectsUnsupportedBcryptCosts(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("password"), minSupportedBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, cost := range []int{minSupportedBcryptCost - 1, maxSupportedBcryptCost + 1, 31} {
		t.Run(fmt.Sprint(cost), func(t *testing.T) {
			invalid := append([]byte(nil), hash...)
			copy(invalid[4:6], fmt.Sprintf("%02d", cost))
			authenticator, problems := NewBasic(config.BasicAuth{Users: map[string]config.BasicUser{
				"valid.client":   {Principal: "principal", PasswordHash: string(hash)},
				"invalid.client": {Principal: "principal", PasswordHash: string(invalid)},
			}}, secrets.Map{})
			if len(problems) == 0 || authenticator.Ready() {
				t.Fatalf("problems = %v, ready = %v", problems, authenticator.Ready())
			}
			if _, err := authenticator.Authenticate("valid.client", "password"); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("partial authentication remained available: %v", err)
			}
			for _, group := range authenticator.costGroups {
				if group.cost != minSupportedBcryptCost {
					t.Fatalf("unsupported cost reached dummy hash generation: %d", group.cost)
				}
			}
		})
	}
}
