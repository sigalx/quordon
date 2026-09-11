package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/secrets"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnavailable        = errors.New("authentication dependency is unavailable")
)

const (
	minSupportedBcryptCost = bcrypt.DefaultCost
	maxSupportedBcryptCost = 14
)

type Principal struct {
	Name             string
	ClientIdentifier string
}

var canonicalBcryptHash = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)

var bcryptBase64 = base64.NewEncoding(
	"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
).WithPadding(base64.NoPadding).Strict()

type credential struct {
	principal string
	hash      []byte
}

type Basic struct {
	realm     string
	users     map[string]credential
	dummyHash []byte
	ready     bool
}

func NewBasic(cfg config.BasicAuth, resolver secrets.Resolver) (*Basic, []error) {
	dummyHash, err := bcrypt.GenerateFromPassword([]byte("quordon-dummy-password"), bcrypt.DefaultCost)
	if err != nil {
		panic(fmt.Sprintf("create dummy bcrypt hash: %v", err))
	}
	authenticator := &Basic{
		realm:     cfg.Realm,
		users:     make(map[string]credential, len(cfg.Users)),
		dummyHash: dummyHash,
		ready:     true,
	}
	var problems []error
	expectedCost := -1
	for username, user := range cfg.Users {
		hash := user.PasswordHash
		if hash == "" {
			var resolveErr error
			hash, resolveErr = resolver.Resolve(user.PasswordHashSecretRef)
			if resolveErr != nil {
				authenticator.ready = false
				problems = append(problems, fmt.Errorf("resolve Basic Auth credential for %q: %w", username, resolveErr))
				continue
			}
		}
		cost, costErr := validateBcryptHash([]byte(hash))
		if costErr != nil {
			authenticator.ready = false
			problems = append(problems, fmt.Errorf("credential for %q is not a valid bcrypt hash", username))
			continue
		}
		if expectedCost == -1 {
			expectedCost = cost
		} else if cost != expectedCost {
			authenticator.ready = false
			problems = append(problems, errors.New("Basic Auth credentials must use the same bcrypt cost"))
			continue
		}
		authenticator.users[username] = credential{principal: user.Principal, hash: []byte(hash)}
	}
	if expectedCost != -1 && expectedCost != bcrypt.DefaultCost {
		dummyHash, err = bcrypt.GenerateFromPassword([]byte("quordon-dummy-password"), expectedCost)
		if err != nil {
			panic(fmt.Sprintf("create dummy bcrypt hash: %v", err))
		}
		authenticator.dummyHash = dummyHash
	}
	return authenticator, problems
}

func (b *Basic) Realm() string { return b.realm }
func (b *Basic) Ready() bool   { return b.ready }

func (b *Basic) Authenticate(username, password string) (Principal, error) {
	credential, exists := b.users[username]
	hash := b.dummyHash
	if exists {
		hash = credential.hash
	}
	compareErr := bcrypt.CompareHashAndPassword(hash, []byte(password))
	if !b.ready {
		return Principal{}, ErrUnavailable
	}
	if !exists || compareErr != nil {
		return Principal{}, ErrInvalidCredentials
	}
	return Principal{Name: credential.principal, ClientIdentifier: username}, nil
}

func validateBcryptHash(hash []byte) (int, error) {
	if !canonicalBcryptHash.Match(hash) {
		return 0, errors.New("bcrypt hash is not canonically encoded")
	}
	if !canonicalBcryptSegment(hash[7:29], 16) || !canonicalBcryptSegment(hash[29:60], 23) {
		return 0, errors.New("bcrypt hash contains an invalid base64 encoding")
	}
	cost, err := bcrypt.Cost(hash)
	if err != nil {
		return 0, err
	}
	if cost < minSupportedBcryptCost || cost > maxSupportedBcryptCost {
		return 0, fmt.Errorf(
			"bcrypt cost must be between %d and %d",
			minSupportedBcryptCost,
			maxSupportedBcryptCost,
		)
	}
	return cost, nil
}

func canonicalBcryptSegment(encoded []byte, expectedBytes int) bool {
	decoded, err := bcryptBase64.DecodeString(string(encoded))
	return err == nil && len(decoded) == expectedBytes && bcryptBase64.EncodeToString(decoded) == string(encoded)
}
