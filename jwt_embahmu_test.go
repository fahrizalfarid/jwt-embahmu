package jwtembahmu

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
	"time"
)

const keyStr = "ecff723f7dba4aa8ed595e132ef6e54eff2ca6075f6e065b8024ceb0bda5d754"
const tokenStr = "p9oAvy3dazvTquWBqc2ArRhgChdXvPF7ujgLEvJ71f469BZ85P41AWpBWfWf2kcFFTp3az8yRKeUmteUrCziJBmMz7P7awuzFGctpo1rw0nn3pD+77ZAWVPOLbN6S2L7XEbB1omA1/6JqrTxWLmc5GPvSznLmHlOxTF1T8nzTbc="

func TestGenerateNonce(t *testing.T) {
	nonce, err := NewJwtEmbahmu().generateNonce()
	if err != nil {
		t.Error(err)
	}
	if nonce == nil {
		t.Error("nil nonce")
	}
}

func TestEncryptJwtEmbahmu(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Error("key generator must be nil")
	}

	if len(key) < 32 {
		t.Error("the key must be in 32 byte")
	}

	key, err := hex.DecodeString(keyStr)
	if err != nil {
		t.Error(err)
	}

	if len(key) < 32 {
		t.Error("the key must be in 32 byte")
	}

	e := NewJwtEmbahmu()
	token, err := e.Encrypt(key)
	if err == nil {
		t.Error(err)
	}
	if len(token) != 0 {
		t.Error("token length must be 0")
	}

	e.IssuedAt = time.Now().Unix()
	e.Expiration = time.Now().Add(24 * time.Hour).Unix()
	token, err = e.Encrypt(key)
	if err != nil {
		t.Error(err)
	}

	if len(token) == 0 {
		t.Error("token length is 0")
	}

	if e.Issuer != "Instagram" {
		t.Error("wrong Issuer")
	}

	if e.Subject != "Embahmu" {
		t.Error("wrong Subject")
	}
}

func BenchmarkEncryptJwtEmbahmu(b *testing.B) {
	key := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, key)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		e := NewJwtEmbahmu()
		e.IssuedAt = time.Now().Unix()
		e.Expiration = time.Now().Add(24 * time.Hour).Unix()
		token, err := e.Encrypt(key)
		if err != nil {
			panic(err)
		}
		if len(token) == 0 {
			panic("token length is 0")
		}
	}
}

func TestDecryptJwtEmbahmu(t *testing.T) {
	key, err := hex.DecodeString(keyStr)
	if err != nil {
		t.Error(err)
	}

	if len(key) < 32 {
		t.Error("the key must be in 32 byte")
	}

	e := NewJwtEmbahmu()
	jsonToken, err := e.Decrypt(key, tokenStr)
	if err != nil {
		t.Error(err)
	}
	if jsonToken == nil {
		t.Error("nil token")
	}

	errSubject := e.Validate(Subject("Embahmu"))
	if errSubject != nil {
		t.Error(errSubject)
	}

	errIssuer := e.Validate(IssuedBy("Instagram"))
	if errIssuer != nil {
		t.Error(errIssuer)
	}

	errExpiration := e.Validate(ValidAT(time.Now()))
	if errExpiration != nil {
		t.Error(errExpiration)
	}

	errSubject = e.Validate(Subject("bapakmu"))
	if errSubject == nil {
		t.Error(errSubject)
	}

	errIssuer = e.Validate(IssuedBy("Nasa"))
	if errIssuer == nil {
		t.Error(errIssuer)
	}

	errExpiration = e.Validate(ValidAT(time.Now().Add(2 * 24 * time.Hour)))
	if errExpiration == nil {
		t.Error(errExpiration)
	}
}

func BenchmarkDecryptJwtEmbahmu(b *testing.B) {
	key, err := hex.DecodeString(keyStr)
	if err != nil {
		panic(err)
	}

	if len(key) < 32 {
		panic("the key must be in 32 byte")
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		e := NewJwtEmbahmu()
		jsonToken, err := e.Decrypt(key, tokenStr)
		if err != nil {
			panic(err)
		}
		if jsonToken == nil {
			panic("nil token")
		}
	}
}
