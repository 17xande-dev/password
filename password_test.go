package password

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var cheapParams = Params{Memory: 64, Time: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

func TestHashAndRehash(t *testing.T) {
	t.Cleanup(SetParamsForTesting(cheapParams))
	isolateSemaphore(t)

	// The library doesn't apply a policy, even to an empty password.
	hash := assertHash(t, "")
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("unexpected PHC string: %q", hash)
	}
	// Different accounts using the same password must not get the same hash.
	if second := assertHash(t, ""); second == hash {
		t.Fatalf("second Hash = %q; want a different salt", second)
	}
	assertCheck(t, hash, "", true, false)
	assertCheck(t, hash, "wrong", false, false)

	// Existing users can still log in after defaults change.
	next := cheapParams
	next.Time++
	t.Cleanup(SetParamsForTesting(next))
	assertCheck(t, hash, "", true, true)
	assertCheck(t, hash, "wrong", false, false)
}

func TestDefaultHash(t *testing.T) {
	isolateSemaphore(t)
	hash := assertHash(t, "test password")
	h, err := parse(hash)
	if err != nil || h.params != (Params{65536, 3, 4, 16, 32}) {
		t.Fatalf("default params = %+v, %v", h.params, err)
	}
	assertCheck(t, hash, "test password", true, false)
}

func TestBcryptRehash(t *testing.T) {
	hash := makeBcrypt(t, "test password")
	for _, minor := range []string{"a", "b", "y"} {
		t.Run(minor, func(t *testing.T) {
			isolateSemaphore(t)
			legacy := "$2" + minor + hash[3:]
			if err := Validate(legacy); err != nil {
				t.Fatal(err)
			}
			assertCheck(t, legacy, "test password", true, true)
			assertCheck(t, legacy, "wrong", false, false)
		})
	}
}

func TestRejectsMalformedHashes(t *testing.T) {
	const valid = "$argon2id$v=19$m=64,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	legacy := makeBcrypt(t, "test password")
	tests := []struct{ name, hash string }{
		{"empty", ""},
		{"unsupported", strings.Replace(valid, "argon2id", "argon2i", 1)},
		{"version", strings.Replace(valid, "v=19", "v=18", 1)},
		{"version suffix", strings.Replace(valid, "v=19", "v=19x", 1)},
		{"parameter suffix", strings.Replace(valid, "p=1", "p=1x", 1)},
		{"same parameter twice", strings.Replace(valid, "t=1", "m=1", 1)},
		{"negative memory", strings.Replace(valid, "m=64", "m=-1", 1)},
		{"zero memory", strings.Replace(valid, "m=64", "m=0", 1)},
		{"zero time", strings.Replace(valid, "t=1", "t=0", 1)},
		{"too many passes", strings.Replace(valid, "t=1", "t=4294967295", 1)},
		{"zero lanes", strings.Replace(valid, "p=1", "p=0", 1)},
		{"too many lanes", strings.Replace(valid, "p=1", "p=255", 1)},
		// Enough memory for 17 lanes: only the lane cap should reject this.
		{"over lane cap with enough memory", strings.Replace(valid, "m=64,t=1,p=1", "m=4096,t=1,p=17", 1)},
		{"undersized memory", strings.Replace(valid, "m=64", "m=7", 1)},
		{"empty salt", strings.Replace(valid, "$AAAAAAAAAAAAAAAAAAAAAA$", "$$", 1)},
		{"empty key", valid[:strings.LastIndex(valid, "$")+1]},
		{"oversize key", valid + strings.Repeat("A", 55)},
		{"invalid base64", valid[:len(valid)-1] + "!"},
		{"noncanonical base64", valid[:len(valid)-1] + "B"},
		{"padded base64", valid + "="},
		{"newline in base64", valid[:len(valid)-1] + "\nA"},
		{"extra field", valid + "$extra"},
		{"overlong hash", strings.Repeat("$", 1000)},
		{"short bcrypt", legacy[:len(legacy)-1]},
		{"long bcrypt", legacy + "."},
		{"unsupported bcrypt prefix", "$2x" + legacy[3:]},
		{"bcrypt bad separator", legacy[:6] + "!" + legacy[7:]},
		{"bcrypt bad salt", legacy[:7] + "!" + legacy[8:]},
		{"bcrypt bad checksum", legacy[:29] + "!" + legacy[30:]},
		{"bcrypt noncanonical checksum", legacy[:59] + "/"},
		{"bcrypt cost too low", legacy[:4] + "03" + legacy[6:]},
		{"bcrypt cost too high", legacy[:4] + "31" + legacy[6:]},
	}
	// A write-time check must reject everything that would error at login.
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkFormatRejection(t, tc.hash)
		})
	}
}

func TestVerifyMemoryLimit(t *testing.T) {
	// Validate at the exact limit without allocating a GiB. The next KiB
	// must be refused by both entry points, before any hashing starts.
	const suffix = ",t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := Validate("$argon2id$v=19$m=1048576" + suffix); err != nil {
		t.Fatal(err)
	}
	checkFormatRejection(t, "$argon2id$v=19$m=1048577"+suffix)
}

func checkFormatRejection(t *testing.T, hash string) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // A busy error here would mean we reached acquisition before validating.
	got := Validate(hash)
	ok, rehash, err := Check(ctx, hash, "anything")
	if !errors.Is(got, errHashFormat) || !errors.Is(err, errHashFormat) ||
		got.Error() != err.Error() || ok || rehash {
		t.Fatalf("Validate = %v; Check = (%t, %t, %v); want same format error", got, ok, rehash, err)
	}
}

func assertCheck(t *testing.T, hash, pw string, wantOK, wantRehash bool) {
	t.Helper()
	ctx, cancel := hashingTestContext(t)
	defer cancel()
	if ok, rehash, err := Check(ctx, hash, pw); err != nil || ok != wantOK || rehash != wantRehash {
		t.Fatalf("Check = (%t, %t, %v), want (%t, %t, nil)", ok, rehash, err, wantOK, wantRehash)
	}
	assertEmptySlots(t, currentSlots(), "Check")
}

func assertHash(t *testing.T, pw string) string {
	t.Helper()
	ctx, cancel := hashingTestContext(t)
	defer cancel()
	hash, err := Hash(ctx, pw)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	assertEmptySlots(t, currentSlots(), "Hash")
	return hash
}

func hashingTestContext(t *testing.T) (context.Context, context.CancelFunc) {
	return context.WithTimeout(t.Context(), 10*time.Second)
}

// Isolate occupied slots so a failed test cannot affect the next test.
// Only nonparallel tests with no work in flight can replace the semaphore.
func isolateSemaphore(t *testing.T) {
	saved := currentSlots()
	SetConcurrency(cap(saved))
	t.Cleanup(func() {
		slotsMu.Lock()
		slots = saved
		slotsMu.Unlock()
	})
}

func makeBcrypt(t *testing.T, pw string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}
