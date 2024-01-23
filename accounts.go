package authb

import (
	"errors"
	"fmt"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func NewAccountFromJWT(token string) (Account, error) {
	ac, err := jwt.DecodeAccountClaims(token)
	if err != nil {
		return nil, err
	}

	return &AccountData{
		Claim: ac,
		BaseData: BaseData{
			Loaded:     ac.IssuedAt,
			EntityName: ac.Name,
			Token:      token,
			readOnly:   true,
		},
	}, nil
}

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
	a.Modified = true
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
	if a.BaseData.readOnly {
		return fmt.Errorf("account is read-only")
	}

	var vr jwt.ValidationResults
	a.Claim.Validate(&vr)
	if vr.IsBlocking(true) {
		return vr.Errors()[0]
	}
	// FIXME: the account possibly needs a way to select the key...
	key := a.Operator.Key
	if len(a.Operator.OperatorSigningKeys) > 0 {
		key = a.Operator.OperatorSigningKeys[0]
	}
	return a.issue(key)
}

func (a *AccountData) getRevocations() jwt.RevocationList {
	if a.Claim.Revocations == nil {
		a.Claim.Revocations = jwt.RevocationList{}
	}
	return a.Claim.Revocations
}

func (a *AccountData) getRevocationPrefix() nkeys.PrefixByte {
	return nkeys.PrefixByteUser
}

func (a *AccountData) Revocations() Revocations {
	return &revocations{data: a}
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
	return a
}

func (a *AccountData) Imports() Imports {
	panic("not implemented")
}
