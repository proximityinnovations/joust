package joust_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/bmartel/joust"
)

type MockStorage struct{}

func (MockStorage) Add(string, string) error {
	return nil
}
func (MockStorage) Remove(string, string) error {
	return nil
}
func (MockStorage) RemoveAll(string) error {
	return nil
}
func (MockStorage) Exists(string, string) bool {
	return true
}
func (MockStorage) Flush() error {
	return nil
}

type MockUser struct{}

func (MockUser) Identity() string {
	return "123456"
}

type CustomClaims struct {
	joust.StandardClaims
	Roles []string `json:"roles,omitempty"`
}

var auth = joust.New(&joust.Options{
	Storer:          new(MockStorage),
	SigningKey:      []byte("secret"),
	Domain:          "localhost",
	TokenIdentifier: "id",
	Secure:          false,
	Debug:           true,
	ErrorHandler:    func(w http.ResponseWriter, r *http.Request, err string) {},
})

func TestGenerateToken(t *testing.T) {
	r := new(http.Request)
	r.URL = new(url.URL)

	now := time.Now()
	nowUnix := now.Unix()
	token := auth.GenerateToken(r, &joust.StandardClaims{}, MockUser{}, false)

	tokenClaims := token.Claims.(*joust.StandardClaims)

	if tokenClaims.NotBefore != nowUnix {
		t.Error("NotBefore is not set to current time")
	}
	if tokenClaims.IssuedAt != nowUnix {
		t.Error("IssuedAt is not set to current time")
	}
	if tokenClaims.ExpiresAt != now.Add(time.Duration(60*24*14)*time.Minute).Unix() {
		t.Error("ExpiresAt is not set to expire in the default expiry window")
	}

	t.Logf("%+v", tokenClaims)
}

func TestGenerateTokenCustomClaims(t *testing.T) {
	r := new(http.Request)
	r.URL = new(url.URL)

	now := time.Now()
	nowUnix := now.Unix()

	customClaims := &CustomClaims{
		Roles: []string{"manager", "editor"},
	}

	token := auth.GenerateToken(r, customClaims, MockUser{}, false)

	tokenClaims := token.Claims.(*CustomClaims)

	if tokenClaims.NotBefore != nowUnix {
		t.Error("NotBefore is not set to current time")
	}
	if tokenClaims.IssuedAt != nowUnix {
		t.Error("IssuedAt is not set to current time")
	}
	if tokenClaims.ExpiresAt != now.Add(time.Duration(60*24*14)*time.Minute).Unix() {
		t.Error("ExpiresAt is not set to expire in the default expiry window")
	}
	if len(tokenClaims.Roles) != 2 {
		t.Error("custom claim property was not decoded correctly")
	}

	t.Logf("%+v", tokenClaims)
}
