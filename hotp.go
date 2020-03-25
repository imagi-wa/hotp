package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"math"
)

var (
	Digit = 6
)

func HOTP(k []byte, c []byte) (value uint32) {
	value = truncate(hmacSha1(k, c))
	return
}

func truncate(hs []byte) (d uint32) {
	sbits := dt(hs)
	snum := stToNum(sbits)
	d = snum % uint32(math.Pow10(Digit))
	return
}

func hmacSha1(k []byte, c []byte) (hs []byte) {
	mac := hmac.New(sha1.New, k)
	mac.Write(c)
	hs = mac.Sum(nil)
	return
}

// dt is Dynamic Truncation.
func dt(hs []byte) (p []byte) {
	offsetBits := hs[19] & 0xF
	offset := uint32(offsetBits)
	p = hs[offset : offset+4]
	return
}

func stToNum(sbits []byte) (snum uint32) {
	snum = binary.BigEndian.Uint32(sbits)
	return
}
