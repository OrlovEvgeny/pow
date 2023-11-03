package hashcash

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"time"
)

const (
	// Default values
	defaultBits = 4
	// Date format YYMMDDHHMMSS
	defaultDatetimeLayout = "060102150405"
	defaultNonceSize      = 10
)

type (
	Hashcash struct {
		name       string
		hasher     hash.Hash // sha256 / sha1
		privateKey string
		bits       int
		nonceSize  int
	}

	Options func(*Hashcash)
)

func New(algo HashAlgorithm, opts ...Options) *Hashcash {
	hc := &Hashcash{
		name:      algo.String(),
		hasher:    algo.newHasher(),
		bits:      defaultBits,
		nonceSize: defaultNonceSize,
	}
	for _, opt := range opts {
		opt(hc)
	}
	return hc
}

func WithPrivateKey(key string) Options {
	return func(hc *Hashcash) {
		hc.privateKey = key
	}
}

func WithBits(bits int) Options {
	return func(hc *Hashcash) {
		hc.bits = bits
	}
}

func WithNonceSize(n int) Options {
	return func(hc *Hashcash) {
		hc.nonceSize = n
	}
}

func (hc *Hashcash) MintStamp(resource string, expiredAt time.Time) string {
	return hashSegments{
		version:   1,
		bits:      hc.bits,
		issuedAt:  time.Now(),
		expiredAt: expiredAt,
		resource:  resource,
		algo:      hc.name,
		nonce:     nonce(hc.nonceSize),
	}.sign(hc.privateKey)
}

func Verify(privateKey, stamp string) error {
	segment, err := parseStamp(stamp)
	if err != nil {
		return err
	}
	hc := New(LookupByName(segment.algo), WithPrivateKey(privateKey), WithBits(segment.bits))

	if err := segment.verifySign(hc.privateKey); err != nil {
		return err
	}
	if segment.isExpired() {
		return errors.New("stamp has expired")
	}

	hc.hasher.Reset()
	hc.hasher.Write([]byte(stamp))
	checksum := hc.hasher.Sum(nil)
	if checkBits(hc.hasher, hc.bits, checksum) {
		return nil
	}
	return errors.New("not verified")
}

func checkBits(hasher hash.Hash, bits int, hash []byte) bool {
	hasher.Reset()
	hasher.Write(hash)
	sum := hasher.Sum(nil)
	sumUint64 := binary.BigEndian.Uint64(sum)
	sumBits := strconv.FormatUint(sumUint64, 2)
	zeroes := 64 - len(sumBits)

	return zeroes >= bits
}

func Compute(maxAttempts int, challengeStamp string) (string, error) {
	var (
		bs = make([]byte, 4)
	)
	segments, err := parseStamp(challengeStamp)
	if err != nil {
		return "", err
	}
	hc, err := New(LookupByName(segments.algo), WithBits(segments.bits)), nil
	if err != nil {
		return "", err
	}
	for i := 0; i <= maxAttempts; i++ {
		hc.hasher.Reset()
		binary.LittleEndian.PutUint32(bs, segments.counter)
		stamp := []byte(challengeStamp + ":" + base64.StdEncoding.EncodeToString(bs))
		hc.hasher.Write(stamp)
		checksum := hc.hasher.Sum(nil)
		if checkBits(hc.hasher, segments.bits, checksum) {
			return string(stamp), nil
		}
		segments.counter++
	}
	return "", fmt.Errorf("attempts exceded")
}
