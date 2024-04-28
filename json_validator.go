package jwtembahmu

import (
	"errors"
	"fmt"
	"time"
)

type Validator func(token *JsonToken) error

func (j *JsonToken) Validate(validators ...Validator) error {
	var err error
	if len(validators) == 0 {
		validators = append(validators, ValidAT(time.Now()))
	}
	for _, validator := range validators {
		err = validator(j)
		if err != nil {
			return err
		}
	}
	return nil
}

func ValidAT(t time.Time) Validator {
	return func(token *JsonToken) error {
		if t.Unix() > token.Expiration {
			return errors.New("token has expired")
		}
		return nil
	}
}

func Subject(subject string) Validator {
	return func(token *JsonToken) error {
		if token.Subject != subject {
			return fmt.Errorf("token was not related to subject %s", subject)
		}
		return nil
	}
}

func IssuedBy(issuer string) Validator {
	return func(token *JsonToken) error {
		if token.Issuer != issuer {
			return fmt.Errorf("token was not issued by %s", issuer)
		}
		return nil
	}
}
