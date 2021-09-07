package misc

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"strconv"
	"strings"
	"sync/atomic"
)

var idCounter uint32 = 0
var defaultClientHello string

type SessionUID uint32

func GetSessionUID() SessionUID {
	tmpId := atomic.AddUint32(&idCounter, 1)
	return SessionUID(tmpId)
}

func (s SessionUID) ToString() string {
	return strconv.FormatUint(uint64(s), 10)
}

// getSHA1 returns the SHA1 hash of a string
func GetSHA1(input []byte) []byte {
	hash := sha1.Sum(input)
	return hash[:]
}

// getSHA256 returns the SHA-256 hash of a string
func GetSHA256(input []byte) []byte {
	hash := sha256.Sum256(input)
	return hash[:]
}

func GetMD5(input []byte) []byte {
	hash := md5.Sum(input)
	return hash[:]
}

// min returns the smaller one of two integers
func min(one, two int) int {
	if one < two {
		return one
	}
	return two
}

// opensslFormat adds the PEM beginning and end markers and inserts newlines at the right position
func OpensslFormat(input string, header string, trailer string) string {
	res := ""

	// Newline after 64 characters
	start := 0
	for end := 64; start < len(input)-1; end = min(end+64, len(input)) {
		res += input[start:end] + "\n"
		start = end
	}

	return header + "\n" + res + trailer
}

func ToPostgresArray(input []string) string {
	return "{" + strings.Join(input, ",") + "}"
}
