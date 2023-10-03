package nats_auth

import (
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
