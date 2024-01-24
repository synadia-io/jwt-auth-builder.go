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

func (a *AccountData) Services() ServiceExports {
	return &serviceExports{a}
}

func (a *AccountData) Streams() StreamExports {
	return &streamExports{a}
}

func (a *AccountData) Imports() Imports {
	panic("not implemented")
}

func (a *AccountData) getServices() []ServiceExport {
	var buf []ServiceExport
	for _, e := range a.Claim.Exports {
		if e.IsService() {
			se := &ServiceExportImpl{}
			se.data = a
			se.export = e
			buf = append(buf, se)
		}
	}
	return buf
}

func (a *AccountData) deleteExport(subject string, service bool) (bool, error) {
	if subject == "" {
		return false, errors.New("invalid subject")
	}
	if service {
		for idx, e := range a.Claim.Exports {
			if e.IsService() && e.Subject == jwt.Subject(subject) {
				a.Claim.Exports = append(a.Claim.Exports[:idx], a.Claim.Exports[idx+1:]...)
				return true, a.update()
			}
		}
	} else {
		for idx, e := range a.Claim.Exports {
			if e.IsStream() && e.Subject == jwt.Subject(subject) {
				a.Claim.Exports = append(a.Claim.Exports[:idx], a.Claim.Exports[idx+1:]...)
				return true, a.update()
			}
		}
	}

	return false, nil
}

func (a *AccountData) getService(subject string) ServiceExport {
	for _, e := range a.Claim.Exports {
		if e.IsService() && string(e.Subject) == subject {
			se := &ServiceExportImpl{}
			se.data = a
			se.export = e
			return se
		}
	}
	return nil
}

func (a *AccountData) getStreams() []StreamExport {
	var buf []StreamExport
	for _, e := range a.Claim.Exports {
		if e.IsStream() {
			se := &StreamExportImpl{}
			se.data = a
			se.export = e
			buf = append(buf, se)
		}
	}
	return buf
}

func (a *AccountData) getStream(subject string) StreamExport {
	for _, e := range a.Claim.Exports {
		if e.IsStream() && string(e.Subject) == subject {
			se := &StreamExportImpl{}
			se.data = a
			se.export = e
			return se
		}
	}
	return nil
}

func (a *AccountData) addExport(export *jwt.Export) error {
	if export == nil {
		return errors.New("invalid export")
	}
	if export.Name == "" {
		return errors.New("export name is not specified")
	}
	if export.Type == jwt.Unknown {
		return errors.New("export type is not specified")
	}
	if export.Subject == "" {
		return errors.New("export subject is not specified")
	}

	if export.IsService() {
		if a.getService(string(export.Subject)) != nil {
			return errors.New("service export already exists")
		}
	} else {
		if a.getStream(string(export.Subject)) != nil {
			return errors.New("stream export already exists")
		}
	}
	a.Claim.Exports = append(a.Claim.Exports, export)
	return nil
}

func (a *AccountData) newExport(name string, subject string, kind jwt.ExportType) error {
	export := &jwt.Export{
		Name:    name,
		Subject: jwt.Subject(subject),
		Type:    kind,
	}
	return a.addExport(export)
}
