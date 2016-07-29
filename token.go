package joust

import "github.com/dgrijalva/jwt-go"

// Identifier allows for a unique identity to be provided
type Identifier interface {
	Identity() string
}

// StandardClaims allows passing of a CSRF token
type StandardClaims struct {
	jwt.StandardClaims
}

func (c *StandardClaims) GetID() string {
	return c.Id
}

func (c *StandardClaims) SetIdentity(user Identifier) {
	c.Id = user.Identity()
}

func (c *StandardClaims) GetSubject() string {
	return c.Subject
}

func (c *StandardClaims) SetSubject(sub string) {
	c.Subject = sub
}

func (c *StandardClaims) GetIssuer() string {
	return c.Issuer
}

func (c *StandardClaims) SetIssuer(issuer string) {
	c.Issuer = issuer
}

func (c *StandardClaims) SetIssuedAt(issuedAt int64) {
	c.IssuedAt = issuedAt
}

func (c *StandardClaims) SetNotBefore(notBefore int64) {
	c.NotBefore = notBefore
}

func (c *StandardClaims) SetExpiresAt(expiresAt int64) {
	c.ExpiresAt = expiresAt
}

type Claims interface {
	jwt.Claims
	GetID() string
	SetIdentity(Identifier)
	SetSubject(string)
	GetSubject() string
	GetIssuer() string
	SetIssuer(string)
	SetIssuedAt(int64)
	SetNotBefore(int64)
	SetExpiresAt(int64)
}
