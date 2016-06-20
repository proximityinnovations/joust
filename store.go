package joust

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/garyburd/redigo/redis"
)

// TokenStorer defines the necessary storage methods for managing tokens on the server
type TokenStorer interface {
	Add(string, jwt.Token) error
	Remove(string, jwt.Token) error
	RemoveAll(string) error
	Exists(string, jwt.Token) bool
	Flush() error
}

// NewRedisStore creates a redis implementation of the TokenStorer
func NewRedisStore(connPool *redis.Pool) *RedisStore {
	return &RedisStore{connPool}
}

// RedisStore is a redis implementation of the TokenStorer
type RedisStore struct {
	conn *redis.Pool
}

// Add a token to the user record in redis
func (store *RedisStore) Add(key string, token jwt.Token) error {
	conn := store.conn.Get()
	defer conn.Close()

	_, err := conn.Do("SADD", key, token)

	return err
}

// Remove a token from the user record in redis
func (store *RedisStore) Remove(key string, token jwt.Token) error {
	conn := store.conn.Get()
	defer conn.Close()

	_, err := conn.Do("SREM", key, token)

	return err
}

// RemoveAll tokens from the user record
func (store *RedisStore) RemoveAll(key string) error {
	conn := store.conn.Get()
	defer conn.Close()

	_, err := conn.Do("DEL", key)

	return err
}

// Exists checks for the occurrence of the target token in the user record
func (store *RedisStore) Exists(key string, token jwt.Token) bool {
	conn := store.conn.Get()
	defer conn.Close()

	exists, _ := redis.Bool(conn.Do("SISMEMBER", key, token))

	return exists
}

// Flush will flush all data from redis
func (store *RedisStore) Flush() error {
	conn := store.conn.Get()
	defer conn.Close()

	_, err := conn.Do("FLUSHALL")

	return err
}
