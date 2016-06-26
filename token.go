package joust

import "github.com/dgrijalva/jwt-go"

// Identifier allows for a unique identity to be provided
type Identifier interface {
	Identity() string
}

// StandardWithXSRFClaims allows passing of a xsrf token
type StandardWithXSRFClaims struct {
	jwt.StandardClaims
	XSRF string
}
