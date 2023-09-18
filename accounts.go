package nats_auth

import (
	"errors"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

type accountSigningKeys struct {
	data *AccountData
}

func (as *accountSigningKeys) Add() (string, error) {
	k, err := KeyFor(nkeys.PrefixByteAccount)
	if err != nil {
		return "", err
	}
	as.data.Claim.SigningKeys.Add(k.Public)
	err = as.data.update()
	if err != nil {
		return "", err
	}
	as.data.AccountSigningKeys = append(as.data.AccountSigningKeys, k)
	as.data.Operator.AddedKeys = append(as.data.Operator.AddedKeys, k)
	return k.Public, nil
}

func (as *accountSigningKeys) AddScope(role string) (ScopeLimits, error) {
	k, err := KeyFor(nkeys.PrefixByteAccount)
	if err != nil {
		return nil, err
	}
	conf := jwt.NewUserScope()
	conf.Key = k.Public
	conf.Role = role
	as.data.Claim.SigningKeys.AddScopedSigner(conf)
	if err = as.data.update(); err != nil {
		return nil, err
	}
	as.data.Operator.AddedKeys = append(as.data.Operator.AddedKeys, k)
	as.data.AccountSigningKeys = append(as.data.AccountSigningKeys, k)
	return toScopeLimits(as.data, conf), nil
}

func (as *accountSigningKeys) GetScope(key string) (ScopeLimits, bool) {
	scope, ok := as.data.Claim.SigningKeys.GetScope(key)
	if ok && scope != nil {
		us := scope.(*jwt.UserScope)
		return toScopeLimits(as.data, us), ok
	}
	return nil, ok
}

func (as *accountSigningKeys) GetScopeByRole(role string) ScopeLimits {
	for _, v := range as.data.Claim.SigningKeys {
		if v != nil {
			scope := v.(*jwt.UserScope)
			if scope.Role == role {
				return toScopeLimits(as.data, scope)
			}
		}
	}
	return nil
}

func (as *accountSigningKeys) Delete(key string) (bool, error) {
	_, ok := as.data.Claim.SigningKeys[key]
	if ok {
		delete(as.data.Claim.SigningKeys, key)
		as.data.Operator.DeletedKeys = append(as.data.Operator.DeletedKeys, key)
	}
	err := as.data.Operator.update()
	return ok, err
}

func (as *accountSigningKeys) Rotate(key string) (string, error) {
	v, ok := as.data.Claim.SigningKeys[key]
	if ok {
		k, err := KeyFor(nkeys.PrefixByteAccount)
		if err != nil {
			return "", err
		}
		_, err = as.Delete(key)
		if err != nil {
			return "", err
		}
		if v == nil {
			as.data.Claim.SigningKeys.Add(k.Public)
		} else {
			scope := v.(*jwt.UserScope)
			scope.Key = k.Public
			as.data.Claim.SigningKeys.AddScopedSigner(scope)
		}
		err = as.data.update()
		if err != nil {
			return "", err
		}
		for _, u := range as.data.UserDatas {
			if u.Claim.Issuer == key {
				if err := u.issue(k); err != nil {
					return "", err
				}
			}
		}
		return k.Public, nil
	}
	return "", nil
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

type UsersImpl struct {
	accountData *AccountData
}

func (a *UsersImpl) Add(name string, key string) (User, error) {
	if key == "" {
		key = a.accountData.Key.Public
	}
	k, signingKey, err := a.accountData.getKey(key)
	if err != nil {
		return nil, err
	}
	_, scoped := a.accountData.Claim.SigningKeys.GetScope(key)
	uk, err := KeyFor(nkeys.PrefixByteUser)
	if err != nil {
		return nil, err
	}
	d := &UserData{
		BaseData:    BaseData{EntityName: name, Key: uk},
		AccountData: a.accountData,
		Claim:       jwt.NewUserClaims(uk.Public),
		RejectEdits: scoped,
	}
	d.Claim.Name = name
	if signingKey {
		d.Claim.IssuerAccount = a.accountData.Key.Public
	}
	if scoped {
		d.Claim.UserPermissionLimits = jwt.UserPermissionLimits{}
	}

	d.Token, err = d.Claim.Encode(k.Pair)
	if err != nil {
		return nil, err
	}
	a.accountData.UserDatas = append(a.accountData.UserDatas, d)
	a.accountData.Operator.AddedKeys = append(a.accountData.Operator.AddedKeys, uk)
	return d, nil
}

func (a *UsersImpl) Get(name string) User {
	for _, u := range a.accountData.UserDatas {
		if u.EntityName == name || u.Claim.Subject == name {
			return u
		}
	}
	return nil
}

func (a *UsersImpl) List() []User {
	v := make([]User, len(a.accountData.UserDatas))
	for idx, u := range a.accountData.UserDatas {
		v[idx] = u
	}
	return v
}

func (a *UsersImpl) Delete(name string) error {
	for idx, u := range a.accountData.UserDatas {
		if u.EntityName == name || u.Claim.Subject == name {
			a.accountData.DeletedUsers = append(a.accountData.DeletedUsers, u)
			a.accountData.UserDatas = append(a.accountData.UserDatas[:idx], a.accountData.UserDatas[idx+1:]...)
			a.accountData.Operator.DeletedKeys = append(a.accountData.Operator.DeletedKeys, u.Key.Public)
		}
	}
	return nil
}
