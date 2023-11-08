package authb

import (
	"encoding/json"
	"errors"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd"
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
