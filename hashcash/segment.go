package hashcash

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

type hashSegments struct {
	version int
	// Number of leading zeros.
	// defaultBits = 4
	bits int
	// if the stamp was minted more than the specified amount of time ago, it is considered expired.
	// If this option is not used, by default stamps expire after 28 days.
	// Date format YYMMDDhhmmss
	issuedAt  time.Time
	expiredAt time.Time
	// resource string (eg IP address, email address, cmd)
	resource string
	// Hash Algorithm (SHA1, SHA256, SHA512)
	algo string
	// String of random characters from alphabet a-zA-Z0-9+/= to avoid preimage with other sender's stamps
	nonce string
	// Sign
	signature string
	// To find a stamp with the desired number of preimage bits need to try lots of different strings this counter is incremented on each try.
	// The Counter is also composed of characters from the alphabet a-zA-Z0-9+/=. (Note an implementation is not required to count sequentially).
	counter uint32
}

func parseStamp(stamp string) (hashSegments, error) {
	splitedStamp := strings.Split(stamp, ":")
	if len(splitedStamp) < 8 {
		return hashSegments{}, errors.New("invalid stamp")
	}
	version, err := strconv.Atoi(splitedStamp[0])
	if err != nil {
		return hashSegments{}, err
	}

	bits, err := strconv.Atoi(splitedStamp[1])
	if err != nil {
		return hashSegments{}, err
	}

	issuedAt, err := time.Parse(defaultDatetimeLayout, splitedStamp[2])
	if err != nil {
		return hashSegments{}, err
	}

	expiredAt, err := time.Parse(defaultDatetimeLayout, splitedStamp[3])
	if err != nil {
		return hashSegments{}, err
	}

	var counter uint32
	if len(splitedStamp) > 8 {
		bs, err := base64.StdEncoding.DecodeString(splitedStamp[8])
		if err != nil {
			return hashSegments{}, err
		}
		counter = binary.LittleEndian.Uint32(bs)
	}

	return hashSegments{
		version:   version,
		bits:      bits,
		issuedAt:  issuedAt,
		expiredAt: expiredAt,
		resource:  splitedStamp[4],
		algo:      splitedStamp[5],
		nonce:     splitedStamp[6],
		signature: splitedStamp[7],
		counter:   counter,
	}, nil
}

func (h hashSegments) String() string {
	sb := strings.Builder{}
	fmt.Fprintf(&sb, "%d:%d:%s:%s:%s:%s:%s", h.version, h.bits, h.issuedAt.Format(defaultDatetimeLayout), h.expiredAt.Format(defaultDatetimeLayout), h.resource, h.algo, h.nonce)
	return sb.String()
}

func (h hashSegments) sign(privateKey string) string {
	signature := sha256.Sum256([]byte(privateKey + h.String()))
	return fmt.Sprintf("%s:%s", h.String(), base64.StdEncoding.EncodeToString(signature[:]))
}

func (h hashSegments) verifySign(privateKey string) error {
	trustSignature := sha256.Sum256([]byte(privateKey + h.String()))
	signature, err := base64.StdEncoding.DecodeString(h.signature)
	if err != nil {
		return err
	}
	if !bytes.Equal(trustSignature[:], signature) {
		return errors.New("invalid signature")
	}
	return nil
}

func (h hashSegments) isExpired() bool {
	return h.expiredAt.Before(time.Now())
}

const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="

func nonce(tsize int) string {
	result := make([]byte, tsize)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}
