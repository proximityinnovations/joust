package joust

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const authParam = "access_token"

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
	// Claims to be en/decoded
	// Default value: &StandardClaims{}
	Claims Claims
	// The function that will return the Key to validate the JWT.
	// It can be either a shared secret or a public key.
	// Default value: nil
	ValidationKeyGetter jwt.Keyfunc
	// The name of the property in the request where the identity information
	// from the JWT will be stored.
	// Default: "user"
	IdentityProperty string
	// The function that will be called when there's an error validating the token
	// Default: onError
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
	// Default: ""
	Audience string
	// Issuer of the token
	// Default: origin server host
	Issuer string
	// Storage identifier for jwt in cookie and query params
	// Default: authParam
	TokenIdentifier string
	// Default: "/"
	Path string
	// Default: ""
	Domain string
	// Default: false
	Secure bool
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

	if options.Claims == nil {
		options.Claims = new(StandardClaims)
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

// Save a user identity to stored token and return encoded token
func (j *Joust) Save(w http.ResponseWriter, r *http.Request, claims Claims, jti Identifier, forever bool) string {
	return j.StoreToken(w, j.GenerateToken(r, claims, jti, forever))
}

// GenerateToken will create a token for the given request user
func (j *Joust) GenerateToken(r *http.Request, claims Claims, jti Identifier, forever bool) *jwt.Token {
	t := time.Now()

	claims.SetIdentity(jti)

	if claims.GetSubject() == "" {
		claims.SetSubject(j.Options.IdentityProperty + ":" + jti.Identity())
	}

	if claims.GetIssuer() == "" || j.Options.Issuer == "" {
		claims.SetIssuer(getDomain(r))
	}

	now := t.Unix()
	claims.SetIssuedAt(now)
	claims.SetNotBefore(now)

	if forever {
		claims.SetExpiresAt(t.Add(ForeverTTL * time.Minute).Unix())
	} else {
		claims.SetExpiresAt(t.Add(time.Duration(j.Options.TTL) * time.Minute).Unix())
	}

	jwtToken := jwt.New(j.Options.SigningMethod)
	jwtToken.Claims = claims

	return jwtToken
}

// EncodeToken will return a base64 encoded string representation of the token
func (j *Joust) EncodeToken(token *jwt.Token) string {
	tokenString, _ := token.SignedString(j.Options.SigningKey)
	return tokenString
}

// DecodeToken will take a base64 encoded string and try to parse a jwt from it
func (j *Joust) DecodeToken(token string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(token, j.Options.Claims, j.Options.ValidationKeyGetter)
}

// StoreToken will store the token in a cookie and return the signed token string
func (j *Joust) StoreToken(w http.ResponseWriter, token *jwt.Token) string {
	tokenEncoded := j.EncodeToken(token)

	cookie := &http.Cookie{
		Name:     j.Options.TokenIdentifier,
		Value:    tokenEncoded,
		Path:     j.Options.Path,
		Secure:   j.Options.Secure,
		HttpOnly: j.Options.HttpOnly,
		Domain:   j.Options.Domain,
		Expires:  time.Now().Add(time.Duration(defaultCookieExpire) * time.Minute),
	}

	http.SetCookie(w, cookie)

	claims := token.Claims.(Claims)
	j.Options.Storer.Add(claims.GetID(), tokenEncoded)

	return tokenEncoded
}

// DeleteToken will delete the cookie holding the token
func (j *Joust) DeleteToken(w http.ResponseWriter, token *jwt.Token) {
	cookie := &http.Cookie{
		Name:   j.Options.TokenIdentifier,
		MaxAge: -1,
		Path:   j.Options.Path,
		Domain: j.Options.Domain,
	}

	http.SetCookie(w, cookie)

	// Remove invalid tokens from storage
	claims := token.Claims.(Claims)
	j.Options.Storer.Remove(claims.GetID(), j.EncodeToken(token))
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

	// Decode and parse the token
	parsedToken, err := j.DecodeToken(token)

	// If an error occurs, call the error handler and return an error
	if err != nil {
		j.Options.ErrorHandler(w, r, err.Error())
		return nil, fmt.Errorf("Error extracting token: %v", err)
	}

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

	claims := parsedToken.Claims.(Claims)

	// Check if the parsed token is valid...
	if !parsedToken.Valid || !j.Options.Storer.Exists(claims.GetID(), token) {
		// Delete the invalid token
		j.DeleteToken(w, parsedToken)

		j.logf("Token is invalid, removing token with jti %s", claims.GetID())
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
