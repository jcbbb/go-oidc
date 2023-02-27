package argon

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("invalid hash")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

type params struct {
	saltLen uint32
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

func Hash(s string) (hash string, err error) {
	p := &params{
		saltLen: 16,
		time:    1,
		memory:  64 * 1024,
		threads: 4,
		keyLen:  32,
	}

	salt, err := generateRandomBytes(p.saltLen)

	if err != nil {
		return "", err
	}

	h := argon2.IDKey([]byte(s), salt, p.time, p.memory, p.threads, p.keyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(h)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.memory, p.time, p.threads, b64Salt, b64Hash)

	return encodedHash, nil
}

func Verify(s, encoded string) (match bool, err error) {
	p, salt, hash, err := decodeHash(encoded)

	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey([]byte(s), salt, p.time, p.memory, p.threads, p.keyLen)

	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}

	return false, nil
}

func decodeHash(encoded string) (p *params, salt, hash []byte, err error) {
	vals := strings.Split(encoded, "$")

	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)

	if err != nil {
		return nil, nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads)

	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}

	p.saltLen = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])

	if err != nil {
		return nil, nil, nil, err
	}

	p.keyLen = uint32(len(hash))

	return p, salt, hash, nil
}
