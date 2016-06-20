package joust

import (
	"fmt"
	"net/http"
	"strings"
)

// TokenExtractor handles retrieving a jwt from the incoming request
type TokenExtractor func(r *http.Request) (string, error)

// FromHeader is a "TokenExtractor" that takes a give request and extracts
// the JWT token from the Authorization header.
func FromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil // No error, just no token
	}

	if len(authHeader) > 6 && strings.ToUpper(authHeader[0:6]) != "BEARER" {
		return "", fmt.Errorf("Authorization header format must be Bearer {token}")
	}

	return authHeader[7:], nil
}

// FromParameter returns a function that extracts the token from the specified
// query string parameter
func FromParameter(param string) TokenExtractor {
	return func(r *http.Request) (string, error) {
		return r.URL.Query().Get(param), nil
	}
}

// FromCookie returns a function that extracts the token from a cookie specified
// by the name parameter
func FromCookie(name string) TokenExtractor {
	return func(r *http.Request) (string, error) {
		cookie, err := r.Cookie(name)
		return cookie.Value, err
	}
}

// FirstOf returns a function that runs multiple token extractors and takes the
// first token it finds
func FirstOf(extractors ...TokenExtractor) TokenExtractor {
	return func(r *http.Request) (string, error) {
		for _, ex := range extractors {
			token, err := ex(r)
			if err != nil {
				return "", err
			}
			if token != "" {
				return token, nil
			}
		}
		return "", nil
	}
}
