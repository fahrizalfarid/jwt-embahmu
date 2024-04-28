package jwtembahmu

type JsonToken struct {
	Issuer     string
	Subject    string
	Expiration int64
	IssuedAt   int64
}

type JwtEmbahmu interface {
	Encrypt(key []byte) (string, error)
	Decrypt(key []byte, token string) (*JsonToken, error)
}

func NewJwtEmbahmu() *JsonToken {
	return &JsonToken{}
}
