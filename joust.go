package joust

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

type errorHandler func(w http.ResponseWriter, r *http.Request, err string)

// TokenExtractor handles retrieving a jwt from the incoming request
type TokenExtractor func(r *http.Request) (string, error)

// Options is a struct for specifying configuration options for the middleware.
type Options struct {
	// The function that will return the Key to validate the JWT.
	// It can be either a shared secret or a public key.
	// Default value: nil
	ValidationKeyGetter jwt.Keyfunc
	// The name of the property in the request where the identity information
	// from the JWT will be stored.
	// Default value: "user"
	IdentityProperty string
	// The function that will be called when there's an error validating the token
	// Default value:
	ErrorHandler errorHandler
	// A boolean indicating if the credentials are required or not
	// Default value: false
	CredentialsOptional bool
	// A function that extracts the token from the request
	// Default: FromAuthHeader (i.e., from Authorization header as bearer token)
	Extractor TokenExtractor
	// Debug flag turns on debugging output
	// Default: false
	Debug bool
	// When set, all requests with the OPTIONS method will use authentication
	// Default: false
	EnableAuthOnOptions bool
	// When set, the middelware verifies that tokens are signed with the specific signing algorithm
	// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
	// Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
	// Default: nil
	SigningMethod jwt.SigningMethod
}

func (m *Middleware) logf(format string, args ...interface{}) {
	if m.Options.Debug {
		log.Printf(format, args...)
	}
}

func onError(w http.ResponseWriter, r *http.Request, err string) {
	http.Error(w, err, http.StatusUnauthorized)
}

func New(options Options) *Middleware {
	return &Middleware{options}
}

func Default() *Middleware {
	return &Middleware{Options{
		IdentityProperty: "user",
		ErrorHandler:     onError,
		Extractor:        FromAuthHeader,
		SigningMethod:    jwt.SigningMethodHS256,
	}}
}

type Middleware struct {
	Options Options
}

// FromAuthHeader is a "TokenExtractor" that takes a give request and extracts
// the JWT token from the Authorization header.
func FromAuthHeader(r *http.Request) (string, error) {
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

func (m *Middleware) ValidateToken(w http.ResponseWriter, r *http.Request) (*jwt.Token, error) {
	if !m.Options.EnableAuthOnOptions {
		if r.Method == "OPTIONS" {
			return nil, nil
		}
	}

	// Use the specified token extractor to extract a token from the request
	token, err := m.Options.Extractor(r)

	// If debugging is turned on, log the outcome
	if err != nil {
		m.logf("Error extracting JWT: %v", err)
	} else {
		m.logf("Token extracted: %s", token)
	}

	// If an error occurs, call the error handler and return an error
	if err != nil {
		m.Options.ErrorHandler(w, r, err.Error())
		return nil, fmt.Errorf("Error extracting token: %v", err)
	}

	// If the token is empty...
	if token == "" {
		errorMsg := "Required authorization token not found"
		m.Options.ErrorHandler(w, r, errorMsg)
		return nil, fmt.Errorf(errorMsg)
	}

	// Now parse the token
	parsedToken, err := jwt.Parse(token, m.Options.ValidationKeyGetter)

	// Check if there was an error in parsing...
	if err != nil {
		m.logf("Error parsing token: %v", err)
		m.Options.ErrorHandler(w, r, err.Error())
		return nil, fmt.Errorf("Error parsing token: %v", err)
	}

	if m.Options.SigningMethod != nil && m.Options.SigningMethod.Alg() != parsedToken.Header["alg"] {
		message := fmt.Sprintf(
			"Expected %s signing method but token specified %s",
			m.Options.SigningMethod.Alg(),
			parsedToken.Header["alg"],
		)
		m.logf("Error validating token algorithm: %s", message)
		m.Options.ErrorHandler(w, r, errors.New(message).Error())
		return nil, fmt.Errorf("Error validating token algorithm: %s", message)
	}

	// Check if the parsed token is valid...
	if !parsedToken.Valid {
		m.logf("Token is invalid")
		m.Options.ErrorHandler(w, r, "The token isn't valid")
		return nil, fmt.Errorf("Token is invalid")
	}

	m.logf("JWT: %v", parsedToken)

	return parsedToken, nil
}
