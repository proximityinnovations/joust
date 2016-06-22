package joust

import (
	"time"

	"github.com/garyburd/redigo/redis"
)

// TokenStorer defines the necessary storage methods for managing tokens on the server
type TokenStorer interface {
	Add(string, string) error
	Remove(string, string) error
	RemoveAll(string) error
	Exists(string, string) bool
	Flush() error
}

// NewRedisStore creates a redis implementation of the TokenStorer
func NewRedisStore(host string, password string, defaultExpiration time.Duration) *RedisStore {
	var connPool = &redis.Pool{
		MaxIdle:     5,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			// the redis protocol should probably be made sett-able
			c, err := redis.Dial("tcp", host)
			if err != nil {
				return nil, err
			}
			if len(password) > 0 {
				if _, err := c.Do("AUTH", password); err != nil {
					c.Close()
					return nil, err
				}
			} else {
				// check with PING
				if _, err := c.Do("PING"); err != nil {
					c.Close()
					return nil, err
				}
			}
			return c, err
		},
		// custom connection test method
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			if _, err := c.Do("PING"); err != nil {
				return err
			}
			return nil
		},
	}
	return &RedisStore{connPool}
}

// RedisStore is a redis implementation of the TokenStorer
type RedisStore struct {
	conn *redis.Pool
}

// Add a token to the user record in redis
func (store *RedisStore) Add(key string, token string) error {
	conn := store.conn.Get()
	defer conn.Close()

	_, err := conn.Do("SADD", key, token)

	return err
}

// Remove a token from the user record in redis
func (store *RedisStore) Remove(key string, token string) error {
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
func (store *RedisStore) Exists(key string, token string) bool {
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
