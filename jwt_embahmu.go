package jwtembahmu

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

func (j *JsonToken) generateNonce() ([]byte, error) {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func (j *JsonToken) Encrypt(key []byte) (string, error) {
	if len(key) < 32 {
		return "", errors.New("the key must be in 32 byte")
	}

	if j.Expiration == 0 || j.IssuedAt == 0 {
		return "", errors.New("expiration is empty")
	}

	if j.Issuer == "" {
		j.Issuer = "Instagram"
	}

	if j.Subject == "" {
		j.Subject = "Embahmu"
	}

	nonce, err := j.generateNonce()
	if err != nil {
		return "", err
	}

	byteToken, err := json.Marshal(j)
	if err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}

	token := aead.Seal(nonce, nonce, byteToken, nil)
	return base64.StdEncoding.EncodeToString(token), nil

}

func (j *JsonToken) Decrypt(key []byte, token string) (*JsonToken, error) {
	var jsonToken JsonToken

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	m, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext := m[:aead.NonceSize()], m[aead.NonceSize():]
	t, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(t, &jsonToken)
	if err != nil {
		return nil, err
	}

	j.Subject = jsonToken.Subject
	j.Issuer = jsonToken.Issuer
	j.Expiration = jsonToken.Expiration
	j.IssuedAt = jsonToken.IssuedAt

	return &jsonToken, nil
}
