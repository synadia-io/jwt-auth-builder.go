package authb

import (
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

type UsersImpl struct {
	accountData *AccountData
}

func (a *UsersImpl) Add(name string, key string) (User, error) {
	uk, err := a.accountData.Operator.SigningService.NewKey(nkeys.PrefixByteUser)
	if err != nil {
		return nil, err
	}
	return a.add(name, key, uk)
}

func (a *UsersImpl) ImportEphemeral(c *jwt.UserClaims, key string) (User, error) {
	if key == "" {
		key = a.accountData.Key.Public
	}
	k, signingKey, err := a.accountData.getKey(key)
	if err != nil {
		return nil, err
	}

	id, err := KeyFrom(c.Subject, nkeys.PrefixByteUser)
	if err != nil {
		return nil, err
	}
	ok, scoped := a.accountData.ScopedSigningKeys().Contains(key)

	d := &UserData{
		BaseData:    BaseData{EntityName: c.Name, Key: id, Modified: true},
		AccountData: a.accountData,
		Claim:       c,
		RejectEdits: ok && scoped,
		Ephemeral:   true,
	}
	d.Claim.Name = c.Name
	if signingKey {
		d.Claim.IssuerAccount = a.accountData.Key.Public
	}
	if scoped {
		d.Claim.UserPermissionLimits = jwt.UserPermissionLimits{}
	}
	d.Token, err = a.accountData.Operator.SigningService.Sign(d.Claim, k)
	if err != nil {
		return nil, err
	}
	a.accountData.UserDatas = append(a.accountData.UserDatas, d)
	return d, nil
}

func (a *UsersImpl) add(name string, key string, uk *Key) (User, error) {
	if key == "" {
		key = a.accountData.Key.Public
	}
	k, signingKey, err := a.accountData.getKey(key)
	if err != nil {
		return nil, err
	}
	// scope will be nil if just a signing key
	ok, scoped := a.accountData.ScopedSigningKeys().Contains(key)

	d := &UserData{
		BaseData:    BaseData{EntityName: name, Key: uk, Modified: true},
		AccountData: a.accountData,
		Claim:       jwt.NewUserClaims(uk.Public),
		RejectEdits: ok && scoped,
		Ephemeral:   uk.Seed == nil,
	}
	d.Claim.Name = name
	if signingKey {
		d.Claim.IssuerAccount = a.accountData.Key.Public
	}
	if scoped {
		d.Claim.UserPermissionLimits = jwt.UserPermissionLimits{}
	}

	d.Token, err = a.accountData.Operator.SigningService.Sign(d.Claim, k)
	if err != nil {
		return nil, err
	}
	a.accountData.UserDatas = append(a.accountData.UserDatas, d)
	if !d.Ephemeral {
		a.accountData.Operator.AddedKeys = append(a.accountData.Operator.AddedKeys, uk)
	}
	return d, nil
}

func (a *UsersImpl) AddWithIdentity(name string, key string, id string) (User, error) {
	uk, err := KeyFrom(id, nkeys.PrefixByteUser)
	if err != nil {
		return nil, err
	}
	return a.add(name, key, uk)
}

func (a *UsersImpl) Get(name string) (User, error) {
	for _, u := range a.accountData.UserDatas {
		if u.EntityName == name || u.Claim.Subject == name {
			return u, nil
		}
	}
	return nil, ErrNotFound
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
