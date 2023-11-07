package authb

import (
	"errors"
	"github.com/nats-io/jwt/v2"
)

func (a *AccountData) Name() string {
	return a.EntityName
}

func (a *AccountData) issue(key *Key) error {
	var err error
	// self-sign
	if key == nil {
		key = a.Key
	}
	token, err := a.Claim.Encode(key.Pair)
	if err != nil {
		return err
	}
	claim, err := jwt.DecodeAccountClaims(token)
	if err != nil {
		return err
	}
	a.Claim = claim
	a.Token = token
	return nil
}

func (a *AccountData) ScopedSigningKeys() ScopedKeys {
	return &accountSigningKeys{data: a}
}

func (a *AccountData) Subject() string {
	return a.Claim.Subject
}

func (a *AccountData) Issuer() string {
	return a.Claim.Issuer
}

func (a *AccountData) update() error {
	key := a.Operator.Key
	if len(a.Operator.OperatorSigningKeys) > 0 {
		key = a.Operator.OperatorSigningKeys[0]
	}
	return a.issue(key)
}

func (a *AccountData) SetExpiry(exp int64) error {
	a.Claim.Expires = exp
	return a.update()
}

func (a *AccountData) Expiry() int64 {
	return a.Claim.Expires
}

func (a *AccountData) Users() Users {
	return &UsersImpl{accountData: a}
}

func (a *AccountData) getKey(key string) (*Key, bool, error) {
	if key == a.Key.Public {
		return a.Key, false, nil
	}
	for _, k := range a.AccountSigningKeys {
		if k.Public == key {
			return k, true, nil
		}
	}
	return nil, false, errors.New("key not found")
}

func (a *AccountData) Limits() AccountLimits {
	return &accountLimits{data: a}
}

func (a *AccountData) Exports() Exports {
	panic("not implemented")
}

func (a *AccountData) Imports() Imports {
	panic("not implemented")
}
