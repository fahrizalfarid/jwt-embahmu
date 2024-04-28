## encrypt and generate token
```go

const keyStr = "ecff723f7dba4aa8ed595e132ef6e54eff2ca6075f6e065b8024ceb0bda5d754"
const tokenStr = "p9oAvy3dazvTquWBqc2ArRhgChdXvPF7ujgLEvJ71f469BZ85P41AWpBWfWf2kcFFTp3az8yRKeUmteUrCziJBmMz7P7awuzFGctpo1rw0nn3pD+77ZAWVPOLbN6S2L7XEbB1omA1/6JqrTxWLmc5GPvSznLmHlOxTF1T8nzTbc="

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
```

## decrypt and validate token
```go
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
```

## test
```bash
ok  	github.com/fahrizalfarid/jwt-embahmu	0.171s	coverage: 84.1% of statements
```

## benchtest
```bash
goos: windows
goarch: amd64
pkg: github.com/fahrizalfarid/jwt-embahmu
cpu: AMD Ryzen 5 4600H with Radeon Graphics         
BenchmarkEncryptJwtEmbahmu-12    	  861987	      1318 ns/op	     680 B/op	       7 allocs/op
BenchmarkDecryptJwtEmbahmu-12    	  527434	      2329 ns/op	     768 B/op	      13 allocs/op
PASS
coverage: 52.4% of statements
ok  	github.com/fahrizalfarid/jwt-embahmu	2.561s
```