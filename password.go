// Package password hashes and verifies credentials without applying password policy.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Params are the Argon2id settings encoded in a PHC hash.
type Params struct {
	Memory      uint32 // KiB
	Time        uint32 // passes over memory
	Parallelism uint8  // lanes
	SaltLength  uint32 // bytes
	KeyLength   uint32 // bytes
}

// DefaultParams is RFC 9106's second recommended configuration. Treat this
// value as read-only; tests can use SetParamsForTesting to override the cost.
var DefaultParams = Params{Memory: 64 * 1024, Time: 3, Parallelism: 4, SaltLength: 16, KeyLength: 32}

var params = DefaultParams

// SetParamsForTesting changes the cost and rehash target until restore is called.
// Use it only in tests, before starting workers and after they finish when
// restoring; it cannot be used in parallel tests. It panics on invalid params.
func SetParamsForTesting(p Params) (restore func()) {
	if err := validateParams(p); err != nil {
		panic(err)
	}
	old := params
	params = p
	return func() { params = old }
}

var (
	slotsMu sync.Mutex
	slots   = make(chan struct{}, max(2, min(runtime.NumCPU(), 4)))
)

// SetConcurrency sets the process-wide cap shared by Hash, Check and CheckDummy.
// Call it before serving: in-flight calls keep using the previous semaphore,
// so resizing during traffic can temporarily exceed the new limit. Values
// below one are treated as one.
func SetConcurrency(n int) {
	s := make(chan struct{}, max(1, n))
	slotsMu.Lock()
	slots = s
	slotsMu.Unlock()
}

func currentSlots() chan struct{} {
	slotsMu.Lock()
	defer slotsMu.Unlock()
	return slots
}

// ErrBusy means the context ended before a slot could be used. The returned
// error also matches context.Canceled or context.DeadlineExceeded via errors.Is.
var ErrBusy = errors.New("password: context ended before acquiring a hashing slot")

func acquire(ctx context.Context) (release func(), err error) {
	// Return the token to the semaphore that granted it, even after a resize.
	s := currentSlots()
	select {
	case s <- struct{}{}:
		// Both select cases can be ready; do not start hashing for a canceled request.
		if err := ctx.Err(); err != nil {
			<-s
			return nil, fmt.Errorf("%w: %w", ErrBusy, err)
		}
		return func() { <-s }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrBusy, ctx.Err())
	}
}

// A test can hold a derivation open to prove the public operations share the
// semaphore without depending on how long Argon2 takes on the test machine.
var deriveKey = argon2.IDKey

// Hash returns an Argon2id hash in PHC format with a fresh random salt.
// The context bounds the wait for a slot, not the derivation once started.
func Hash(ctx context.Context, pw string) (string, error) {
	release, err := acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()

	p := params
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: generate salt: %w", err)
	}
	key := deriveKey([]byte(pw), salt, p.Time, p.Memory, p.Parallelism, p.KeyLength)
	defer clear(key)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Check verifies a stored Argon2id or legacy bcrypt hash. It reports rehash only
// on a match, when the hash uses bcrypt or differs from the current parameters.
// Malformed or unsupported hashes return an error, not a password mismatch.
func Check(ctx context.Context, hash, pw string) (ok, rehash bool, err error) {
	h, err := parse(hash)
	if err != nil {
		return false, false, err
	}
	if h.bcrypt == nil {
		ok, err := checkArgon2id(ctx, h, pw)
		return ok, ok && h.params != params, err
	}

	release, err := acquire(ctx)
	if err != nil {
		return false, false, err
	}
	defer release()
	switch err := bcrypt.CompareHashAndPassword(h.bcrypt, []byte(pw)); err {
	case nil:
		return true, true, nil
	case bcrypt.ErrMismatchedHashAndPassword:
		return false, false, nil
	default:
		return false, false, fmt.Errorf("password: verify bcrypt: %w", err)
	}
}

// CheckDummy spends the cost of a failed Check at the current Argon2id
// settings, so an unknown account need not take a fast path. It never matches.
func CheckDummy(ctx context.Context, pw string) (bool, error) {
	p := params
	// There is no credential to protect. Synthetic salt and key avoid an extra
	// first-use derivation and follow the active settings even in tests.
	h := parsedHash{params: p, salt: make([]byte, p.SaltLength), key: make([]byte, p.KeyLength)}
	_, err := checkArgon2id(ctx, h, pw)
	return false, err
}

func checkArgon2id(ctx context.Context, h parsedHash, pw string) (bool, error) {
	release, err := acquire(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	p := h.params
	got := deriveKey([]byte(pw), h.salt, p.Time, p.Memory, p.Parallelism, p.KeyLength)
	defer clear(got)
	// A comparison that stops at the first mismatch can leak how much of the key matched.
	return subtle.ConstantTimeCompare(got, h.key) == 1, nil
}
