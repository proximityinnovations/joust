package joust

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"time"
)

const (
	MD5 = iota
	SHA256
)
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

const emailAddr = `^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`

var IsEmail = regexp.MustCompile(emailAddr)

func getDomain(r *http.Request) string {
	return fmt.Sprintf("%s://%s", r.URL.Scheme, r.URL.Host)
}

func Hash(hType int, text string) string {
	var val [16]byte

	switch hType {
	case MD5:
		val = md5.Sum([]byte(text))
	case SHA256:
		val = md5.Sum([]byte(text))
	default:
		return ""
	}

	return hex.EncodeToString(val[:])
}

// Secure a password string through hashing
func Secure(password string, n int) (string, error) {
	// Ensure a user doesn't go below 10 rounds of hashing
	if n < 10 {
		n = 10
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), n)
	if err != nil {
		return "", err
	}

	return hashedPassword, nil
}

// Check a hashed password against a password string to see if they are a match
func Check(localPass string, hashedPass string) error {
	err = bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(localPass))
	if err != nil {
		return fmt.Errorf("passwords do not match")
	}

	return nil
}

// RandomStr generates a randomized string of a fixed length
func RandomStr(n int) string {
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
