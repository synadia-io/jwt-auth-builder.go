package nats_auth

import (
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd"

	"encoding/json"
	"errors"
)

type operatorSigningKeys struct {
	data *OperatorData
}

func (os *operatorSigningKeys) Add() (string, error) {
	k, err := os.add()
	if err != nil {
		return "", err
	}
	return k.Public, nil
}

func (os *operatorSigningKeys) add() (*Key, error) {
	key, err := KeyFor(nkeys.PrefixByteOperator)
	if err != nil {
		return nil, err
	}
	err = os.data.update()
	if err != nil {
		return nil, err
	}
	os.data.AddedKeys = append(os.data.AddedKeys, key)
	os.data.OperatorSigningKeys = append(os.data.OperatorSigningKeys, key)
	os.data.Claim.SigningKeys = append(os.data.Claim.SigningKeys, key.Public)
	return key, nil
}

func (os *operatorSigningKeys) Delete(key string) (bool, error) {
	for idx, k := range os.data.Claim.SigningKeys {
		if k == key {
			os.data.DeletedKeys = append(os.data.DeletedKeys, key)
			os.data.Claim.SigningKeys = append(os.data.Claim.SigningKeys[:idx], os.data.Claim.SigningKeys[idx+1:]...)
			return true, os.data.update()
		}
	}
	return false, nil
}

func (os *operatorSigningKeys) Rotate(key string) (string, error) {
	k, err := os.add()
	if err != nil {
		return "", err
	}
	ok, err := os.Delete(key)
	if !ok || err != nil {
		return "", err
	}

	// reissue all the accounts that were issued with the rotated signing key
	for _, a := range os.data.AccountDatas {
		if a.Claim.Issuer == key {
			err := a.issue(k)
			if err != nil {
				return "", err
			}
		}
	}
	return k.Public, err
}

func (os *operatorSigningKeys) List() []string {
	v := make([]string, len(os.data.Claim.SigningKeys))
	copy(v, os.data.Claim.SigningKeys)
	return v
}

func (o *OperatorData) String() string {
	d, _ := json.MarshalIndent(o.Claim, "", "  ")
	return string(d)
}

func (o *OperatorData) Name() string {
	return o.EntityName
}

func (o *OperatorData) Subject() string {
	return o.Claim.Subject
}

func (o *OperatorData) Accounts() Accounts {
	return o
}

func (o *OperatorData) SigningKeys() Keys {
	return &operatorSigningKeys{data: o}
}

func (o *OperatorData) SetAccountServerURL(url string) error {
	o.Claim.AccountServerURL = url
	return o.update()
}

func (o *OperatorData) AccountServerURL() string {
	return o.Claim.AccountServerURL
}

func (o *OperatorData) SetOperatorServiceURL(url ...string) error {
	o.Claim.OperatorServiceURLs = url
	return o.update()
}

func (o *OperatorData) OperatorServiceURLs() []string {
	return o.Claim.OperatorServiceURLs
}

func (o *OperatorData) SystemAccount() Account {
	id := o.Claim.SystemAccount
	if id == "" {
		return nil
	}
	return o.Accounts().Get(id)
}

func (o *OperatorData) SetSystemAccount(account Account) error {
	if account == nil {
		o.Claim.SystemAccount = ""
	} else {
		o.Claim.SystemAccount = account.Subject()
	}
	return o.update()
}

func (o *OperatorData) Add(name string) (Account, error) {
	sk, err := KeyFor(nkeys.PrefixByteAccount)
	if err != nil {
		return nil, err
	}
	ac := jwt.NewAccountClaims(sk.Public)
	ac.Name = name

	ad := &AccountData{
		BaseData: BaseData{Key: sk, EntityName: name},
		Claim:    ac,
		Operator: o,
	}
	ad.Operator.AddedKeys = append(ad.Operator.AddedKeys, sk)
	if err := ad.update(); err != nil {
		return nil, err
	}
	o.AccountDatas = append(o.AccountDatas, ad)
	return ad, nil
}

func (o *OperatorData) Delete(name string) error {
	for idx, a := range o.AccountDatas {
		if a.EntityName == name || a.Subject() == name {
			if a.Subject() == o.Claim.SystemAccount {
				return errors.New("cannot delete system account")
			}
			o.DeletedAccounts = append(o.DeletedAccounts, a)
			o.AccountDatas = append(o.AccountDatas[:idx], o.AccountDatas[idx+1:]...)
		}
	}
	return nil
}

func (o *OperatorData) Get(name string) Account {
	for _, a := range o.AccountDatas {
		if a.EntityName == name || a.Subject() == name {
			return a
		}
	}
	return nil
}

func (o *OperatorData) List() []Account {
	v := make([]Account, len(o.AccountDatas))
	for i, a := range o.AccountDatas {
		v[i] = a
	}
	return v
}

func (o *OperatorData) update() error {
	var err error
	var vr jwt.ValidationResults
	o.Claim.Validate(&vr)
	if vr.IsBlocking(true) {
		return vr.Errors()[0]
	}

	token, err := o.Claim.Encode(o.Key.Pair)
	if err != nil {
		return err
	}
	claims, err := jwt.DecodeOperatorClaims(token)
	if err != nil {
		return err
	}
	o.Claim = claims
	o.Token = token

	return nil
}

func (o *OperatorData) MemResolver() ([]byte, error) {
	builder := cmd.NewMemResolverConfigBuilder()
	if err := builder.Add([]byte(o.Token)); err != nil {
		return nil, err
	}
	sys := o.SystemAccount()
	if sys != nil {
		if err := builder.SetSystemAccount(sys.Subject()); err != nil {
			return nil, err
		}
	}
	for _, a := range o.Accounts().List() {
		ad := a.(*AccountData)
		if err := builder.Add([]byte(ad.Token)); err != nil {
			return nil, err
		}
	}
	return builder.Generate()
}
