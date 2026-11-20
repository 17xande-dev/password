package password

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	maxVerifyMemory = 1 << 20 // 1 GiB in KiB
	maxVerifyTime   = 10
	maxVerifyLanes  = 16
	maxSaltKeyBytes = 64
	maxVerifyCost   = 16 // bcrypt work doubles with each cost increment
	maxHashBytes    = 256
)

var (
	errHashFormat  = errors.New("password: malformed or unsupported hash")
	phcEncoding    = base64.RawStdEncoding.Strict()
	bcryptEncoding = base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").
			WithPadding(base64.NoPadding).Strict()
)

// Validate checks that a stored hash is safe to verify without running its KDF.
// Use it before persisting a precomputed hash, where a mistake can lock someone out.
func Validate(hash string) error {
	_, err := parse(hash)
	return err
}

type parsedHash struct {
	params Params
	salt   []byte
	key    []byte
	bcrypt []byte
}

func parse(hash string) (parsedHash, error) {
	// Bound parsing and decoding work as well as the eventual derivation.
	if len(hash) > maxHashBytes || strings.ContainsAny(hash, "\r\n") {
		return parsedHash{}, errHashFormat
	}
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		return parseArgon2id(hash)
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		return parseBcrypt(hash)
	default:
		return parsedHash{}, errHashFormat
	}
}

func parseArgon2id(hash string) (parsedHash, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[2] != "v=19" {
		return parsedHash{}, errHashFormat
	}
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return parsedHash{}, errHashFormat
	}
	memory, mOK := parseNumber(fields[0], "m=", 32)
	time, tOK := parseNumber(fields[1], "t=", 32)
	lanes, pOK := parseNumber(fields[2], "p=", 8)
	if !mOK || !tOK || !pOK {
		return parsedHash{}, errHashFormat
	}
	salt, saltErr := phcEncoding.DecodeString(parts[4])
	key, keyErr := phcEncoding.DecodeString(parts[5])
	if saltErr != nil || keyErr != nil {
		return parsedHash{}, errHashFormat
	}
	p := Params{uint32(memory), uint32(time), uint8(lanes), uint32(len(salt)), uint32(len(key))}
	if err := validateParams(p); err != nil {
		return parsedHash{}, err
	}
	return parsedHash{params: p, salt: salt, key: key}, nil
}

func parseNumber(field, prefix string, bits int) (uint64, bool) {
	value, ok := strings.CutPrefix(field, prefix)
	if !ok {
		return 0, false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(value, 10, bits)
	return n, err == nil
}

func validateParams(p Params) error {
	if p.Memory > maxVerifyMemory {
		return fmt.Errorf("%w: Argon2id memory exceeds %d KiB", errHashFormat, maxVerifyMemory)
	}
	// Argon2 requires at least eight blocks per lane. Bound the number of
	// passes, lanes and decoded lengths so corrupt rows cannot cost unbounded work.
	if p.Memory < 8*uint32(p.Parallelism) ||
		p.Time == 0 || p.Time > maxVerifyTime ||
		p.Parallelism == 0 || p.Parallelism > maxVerifyLanes ||
		p.SaltLength < 8 || p.SaltLength > maxSaltKeyBytes ||
		p.KeyLength < 4 || p.KeyLength > maxSaltKeyBytes {
		return fmt.Errorf("%w: Argon2id parameters out of bounds", errHashFormat)
	}
	return nil
}

func parseBcrypt(hash string) (parsedHash, error) {
	// bcrypt.Cost alone does not validate separators or the encoded payload.
	// Check the entire string here so a malformed digest never looks like a
	// normal wrong password, and Validate needs no expensive verification.
	if len(hash) != 60 || hash[6] != '$' {
		return parsedHash{}, errHashFormat
	}
	cost, ok := parseNumber(hash[4:6], "", 8)
	if !ok || cost < uint64(bcrypt.MinCost) || cost > maxVerifyCost {
		return parsedHash{}, fmt.Errorf("%w: bcrypt cost out of bounds", errHashFormat)
	}
	_, saltErr := bcryptEncoding.DecodeString(hash[7:29])
	_, keyErr := bcryptEncoding.DecodeString(hash[29:])
	if saltErr != nil || keyErr != nil {
		return parsedHash{}, errHashFormat
	}
	return parsedHash{bcrypt: []byte(hash)}, nil
}
