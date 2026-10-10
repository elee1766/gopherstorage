package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// sealer encrypts and authenticates small JSON payloads for cookies.
type sealer struct {
	aead cipher.AEAD
}

func newSealer(secret, purpose string) (*sealer, error) {
	key := sha256.Sum256([]byte("gopherstorage/" + purpose + "\x00" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: aead}, nil
}

type envelope struct {
	Exp  int64           `json:"e"`
	Data json.RawMessage `json:"d"`
}

func (s *sealer) seal(v any, ttl time.Duration) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(envelope{Exp: time.Now().Add(ttl).Unix(), Data: data})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	rand.Read(nonce)
	return base64.RawURLEncoding.EncodeToString(s.aead.Seal(nonce, nonce, plain, nil)), nil
}

var errInvalidCookie = errors.New("invalid or expired cookie")

func (s *sealer) open(token string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return errInvalidCookie
	}
	n := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return errInvalidCookie
	}
	var env envelope
	if err := json.Unmarshal(plain, &env); err != nil || time.Now().Unix() > env.Exp {
		return errInvalidCookie
	}
	return json.Unmarshal(env.Data, v)
}
