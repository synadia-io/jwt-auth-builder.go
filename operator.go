package authb

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

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
	if len(url) == 1 && url[0] == "" {
		o.Claim.OperatorServiceURLs = nil
	} else {
		o.Claim.OperatorServiceURLs = url
	}

	return o.update()
}

func (o *OperatorData) SetExpiry(exp int64) error {
	o.Claim.Expires = exp
	return o.update()
}

func (o *OperatorData) Expiry() int64 {
	return o.Claim.Expires
}

func (o *OperatorData) OperatorServiceURLs() []string {
	return o.Claim.OperatorServiceURLs
}

func (o *OperatorData) SystemAccount() (Account, error) {
	id := o.Claim.SystemAccount
	if id == "" {
		return nil, nil
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
	sk, err := o.SigningService.NewKey(nkeys.PrefixByteAccount)
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

func (o *OperatorData) Get(name string) (Account, error) {
	for _, a := range o.AccountDatas {
		if a.EntityName == name || a.Subject() == name {
			return a, nil
		}
	}
	return nil, ErrNotFound
}

func (o *OperatorData) List() []Account {
	v := make([]Account, len(o.AccountDatas))
	for i, a := range o.AccountDatas {
		v[i] = a
	}
	return v
}

func (o *OperatorData) update() error {
	if o.BaseData.readOnly {
		return fmt.Errorf("account is read-only")
	}

	var err error
	var vr jwt.ValidationResults
	o.Claim.Validate(&vr)
	if vr.IsBlocking(true) {
		return vr.Errors()[0]
	}
	token, err := o.SigningService.Sign(o.Claim, o.Key)
	if err != nil {
		return err
	}
	claims, err := jwt.DecodeOperatorClaims(token)
	if err != nil {
		return err
	}
	o.Claim = claims
	o.Token = token
	o.Modified = true

	return nil
}

func (o *OperatorData) IssueClaim(claim jwt.Claims, key string) (string, error) {
	switch claim.(type) {
	case *jwt.UserClaims:
		return "", errors.New("operators cannot issue user claims")
	case *jwt.AuthorizationResponseClaims:
		return "", errors.New("operators cannot issue authorization response claims")
	case *jwt.AuthorizationRequestClaims:
		return "", errors.New("operators cannot issue authorization request claims")
	}

	var k *Key
	if key == "" {
		k = o.Key
	} else {
		for _, sk := range o.OperatorSigningKeys {
			if sk.Public == key {
				k = sk
				break
			}
		}
	}
	if k == nil {
		return "", fmt.Errorf("invalid signing key %w", ErrNotFound)
	}
	return o.SigningService.Sign(claim, k)
}

func (o *OperatorData) MemResolver() ([]byte, error) {
	builder := NewMemResolverConfigBuilder()
	if err := builder.Add([]byte(o.Token)); err != nil {
		return nil, err
	}
	sys, err := o.SystemAccount()
	if err != nil {
		return nil, err
	}
	if !isNil(sys) {
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

func (o *OperatorData) Tags() Tags {
	return &OperatorTags{
		o: o,
	}
}

type OperatorTags struct {
	o *OperatorData
}

func (ot *OperatorTags) Add(tag ...string) error {
	if err := NotEmpty(tag...); err != nil {
		return err
	}
	ot.o.Claim.Tags.Add(tag...)
	return ot.o.update()
}

func (ot *OperatorTags) Remove(tag string) (bool, error) {
	ok := ot.o.Claim.Tags.Contains(tag)
	if ok {
		ot.o.Claim.Tags.Remove(tag)
		err := ot.o.update()
		return ok, err
	}
	return false, nil
}

func (ot *OperatorTags) Contains(tag string) bool {
	return ot.o.Claim.Tags.Contains(tag)
}

func (ot *OperatorTags) Set(tag ...string) error {
	if err := NotEmpty(tag...); err != nil {
		return err
	}
	ot.o.Claim.Tags = tag
	return ot.o.update()
}

func (ot *OperatorTags) All() ([]string, error) {
	return ot.o.Claim.Tags, nil
}

func NotEmpty(s ...string) error {
	if s == nil {
		return errors.New("string cannot be nil")
	}
	for _, t := range s {
		if len(strings.TrimSpace(t)) == 0 {
			return errors.New("string cannot be empty")
		}
	}
	return nil
}
