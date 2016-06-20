package joust

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const authParam = "auth_token"

const identityProperty = "user"

const defaultTTL = 60 * 24 * 14

// ForeverTTL allows a token to live forever (5 years in minutes) for `remember me` purposes
const ForeverTTL = 60 * 24 * 360 * 5

const defaultCookieExpire = ForeverTTL

// ErrorHandler is the function format for handling middleware errors
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err string)

// Options is a struct for specifying configuration options for the middleware.
type Options struct {
	// An implementation of the TokenStorer interface that manages tokens on the server
	// *Required
	Storer TokenStorer
	// Key used for encryption and hash generation
	// *Required
	SigningKey []byte
	// The function that will return the Key to validate the JWT.
	// It can be either a shared secret or a public key.
	// Default value: nil
	ValidationKeyGetter jwt.Keyfunc
	// The name of the property in the request where the identity information
	// from the JWT will be stored.
	// Default: "user"
	IdentityProperty string
	// The function that will be called when there's an error validating the token
	// Default: OnError
	ErrorHandler ErrorHandler
	// A function that extracts the token from the request
	// Default: FromAuthHeader
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
	// Token default time to live in minutes
	// Default: defaultTTL
	TTL int32
	// Valid target audience for the generated tokens
	Audience string
	// Issuer of the token
	Issuer string
	// Storage identifier for jwt in cookie and query params
	TokenIdentifier string
	// Cookie options
	// Default: "/"
	Path string
	// Default: false
	Secure bool
	// Default: ""
	Domain string
	// Default: true
	HttpOnly bool
}

// New returns a pointer to a new middleware configuration based on the provided
// Options
func New(options *Options) *Joust {
	if options.Storer == nil {
		panic("Token storer was not given an implementation")
	}

	if options.SigningKey == nil {
		panic("No signing key was provided")
	}

	if options.ValidationKeyGetter == nil {
		options.ValidationKeyGetter = jwtKeyGetter(options.SigningKey)
	}

	if options.TokenIdentifier == "" {
		options.TokenIdentifier = authParam
	}

	if options.Extractor == nil {
		options.Extractor = FirstOf(FromHeader, FromParameter(options.TokenIdentifier), FromCookie(options.TokenIdentifier))
	}

	if options.ErrorHandler == nil {
		options.ErrorHandler = onError
	}

	if options.IdentityProperty == "" {
		options.IdentityProperty = identityProperty
	}
	if options.SigningMethod == nil {
		options.SigningMethod = jwt.SigningMethodHS256
	}

	if options.Path == "" {
		options.Path = "/"
	}

	if options.TTL == 0 {
		options.TTL = defaultTTL
	}

	options.HttpOnly = true

	return &Joust{options}
}

// Joust provides middleware and token management using jwt
type Joust struct {
	Options *Options
}

// RefreshToken will remove an old token and generate a new one
func (j *Joust) RefreshToken(r *http.Request, currentToken *jwt.Token, user Identifier, forever bool) *jwt.Token {
	j.Options.Storer.Remove(user.Identity(), *currentToken)

	newToken := j.GenerateToken(r, user, forever)

	j.Options.Storer.Add(user.Identity(), *newToken)

	return newToken
}

// GenerateToken will create a token for the given request user
func (j *Joust) GenerateToken(r *http.Request, user Identifier, forever bool) *jwt.Token {
	t := time.Now()

	claims := jwt.StandardClaims{}
	claims.Id = user.Identity()

	url := getDomain(r)
	if j.Options.Issuer == "" {
		claims.Issuer = url
	}

	claims.IssuedAt = t.Unix()
	claims.NotBefore = t.Unix()

	if forever {
		claims.ExpiresAt = t.Add(ForeverTTL * time.Minute).Unix()
	} else {
		claims.ExpiresAt = t.Add(time.Duration(j.Options.TTL) * time.Minute).Unix()
	}

	jwtToken := jwt.New(j.Options.SigningMethod)
	jwtToken.Claims = claims

	return jwtToken
}

// StoreCookie will store the token in a cookie
func (j *Joust) StoreCookie(w http.ResponseWriter, token *jwt.Token) {
	tokenString, _ := token.SignedString(j.Options.SigningKey)
	cookie := &http.Cookie{
		Name:    j.Options.TokenIdentifier,
		Value:   base64.URLEncoding.EncodeToString([]byte(tokenString)),
		Path:    j.Options.Path,
		Domain:  j.Options.Domain,
		Expires: time.Now().Add(time.Duration(defaultCookieExpire) * time.Minute),
	}

	http.SetCookie(w, cookie)
}

// DeleteCookie will delete the cookie holding the token
func (j *Joust) DeleteCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   j.Options.TokenIdentifier,
		MaxAge: -1,
		Path:   j.Options.Path,
		Domain: j.Options.Domain,
	}

	http.SetCookie(w, cookie)
}

// ValidateToken parses and handles token validation for a given request
func (j *Joust) ValidateToken(w http.ResponseWriter, r *http.Request) (*jwt.Token, error) {
	if !j.Options.EnableAuthOnOptions {
		if r.Method == "OPTIONS" {
			return nil, nil
		}
	}

	// Use the specified token extractor to extract a token from the request
	token, err := j.Options.Extractor(r)

	if err != nil {
		j.logf("Error extracting JWT: %v", err)
	} else {
		j.logf("Token extracted: %s", token)
	}

	// If an error occurs, call the error handler and return an error
	if err != nil {
		j.Options.ErrorHandler(w, r, err.Error())
		return nil, fmt.Errorf("Error extracting token: %v", err)
	}

	// If the token is empty...
	if token == "" {
		errorMsg := "Required authorization token not found"
		j.Options.ErrorHandler(w, r, errorMsg)
		return nil, fmt.Errorf(errorMsg)
	}

	// Decode the token
	decodedToken, err := base64.URLEncoding.DecodeString(token)
	// If an error occurs, call the error handler and return an error
	if err != nil {
		j.Options.ErrorHandler(w, r, err.Error())
		return nil, fmt.Errorf("Error extracting token: %v", err)
	}

	// Now parse the token
	parsedToken, err := jwt.Parse(string(decodedToken), j.Options.ValidationKeyGetter)

	// Check if there was an error in parsing...
	if err != nil {
		j.logf("Error parsing token: %v", err)
		j.Options.ErrorHandler(w, r, err.Error())
		return nil, fmt.Errorf("Error parsing token: %v", err)
	}

	if j.Options.SigningMethod != nil && j.Options.SigningMethod.Alg() != parsedToken.Header["alg"] {
		message := fmt.Sprintf(
			"Expected %s signing method but token specified %s",
			j.Options.SigningMethod.Alg(),
			parsedToken.Header["alg"],
		)
		j.logf("Error validating token algorithm: %s", message)
		j.Options.ErrorHandler(w, r, errors.New(message).Error())
		return nil, fmt.Errorf("Error validating token algorithm: %s", message)
	}

	claims := parsedToken.Claims.(jwt.StandardClaims)
	tokenVal := *parsedToken

	// Check if the parsed token is valid...
	if !parsedToken.Valid || !j.Options.Storer.Exists(claims.Id, tokenVal) {

		// Remove invalid tokens from storage
		go j.Options.Storer.Remove(claims.Id, tokenVal)

		// Delete the invalid token cookie
		j.DeleteCookie(w)

		j.logf("Token is invalid, removing token with jti %s", claims.Id)
		j.Options.ErrorHandler(w, r, "The token isn't valid")
		return nil, fmt.Errorf("Token is invalid")
	}

	j.logf("JWT: %v", parsedToken)

	return parsedToken, nil
}

func (j *Joust) logf(format string, args ...interface{}) {
	if j.Options.Debug {
		log.Printf(format, args...)
	}
}

func onError(w http.ResponseWriter, r *http.Request, err string) {
	http.Error(w, err, http.StatusUnauthorized)
}

func jwtKeyGetter(signingKey []byte) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	}
}
