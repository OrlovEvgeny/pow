package hashcash

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

const (
	SHA1 HashAlgorithm = iota
	SHA256
	SHA512
)

type (
	HashAlgorithm uint8

	algorithm struct {
		name  string
		newFn func() hash.Hash
	}
)

var availableAlgorithms = [...]algorithm{
	{
		name:  "SHA-1",
		newFn: sha1.New,
	},
	{
		name:  "SHA-256",
		newFn: sha256.New,
	},
	{
		name:  "SHA-512",
		newFn: sha512.New,
	},
}

func (ha HashAlgorithm) String() string {
	return availableAlgorithms[ha].name
}

func (ha HashAlgorithm) newHasher() hash.Hash {
	return availableAlgorithms[ha].newFn()
}

func LookupByName(name string) HashAlgorithm {
	switch name {
	case SHA1.String():
		return SHA1
	case SHA256.String():
		return SHA256
	case SHA512.String():
		return SHA512
	}
	return SHA1
}
