package joust

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

const (
	md5Hash = iota
	sha256Hash
)
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func getDomain(r *http.Request) string {
	return fmt.Sprintf("%s://%s", r.URL.Scheme, r.URL.Host)
}

func hash(hType int, text string) string {
	var val [16]byte

	switch hType {
	case md5Hash:
		val = md5.Sum([]byte(text))
	case sha256Hash:
		val = md5.Sum([]byte(text))
	default:
		return ""
	}

	return hex.EncodeToString(val[:])
}

// randomStr generates a randomized string of a fixed length
func randomStr(n int) string {
	src := rand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
