package authb

import (
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
)

func (u *UserData) Subject() string {
	return u.Claim.Subject
}

func (u *UserData) Name() string {
	return u.Claim.Name
}

func (u *UserData) IsScoped() bool {
	_, ok := u.AccountData.Claim.SigningKeys.GetScope(u.Claim.Issuer)
	return ok
}

func (u *UserData) issue(key *Key) error {
	token, err := u.AccountData.Operator.SigningService.Sign(u.Claim, key)
	if err != nil {
		return err
	}
	uc, err := jwt.DecodeUserClaims(token)
	if err != nil {
		return err
	}
	u.Claim = uc
	u.Token = token
	return nil
}

func (u *UserData) update() error {
	if u.BaseData.readOnly {
		return fmt.Errorf("account is read-only")
	}

	issuer := u.Claim.Issuer
	k, _, err := u.AccountData.getKey(issuer)
	if err != nil {
		return err
	}
	token, err := u.AccountData.Operator.SigningService.Sign(u.Claim, k)
	if err != nil {
		return err
	}
	claim, err := jwt.DecodeUserClaims(token)
	if err != nil {
		return err
	}
	u.Claim = claim
	u.Token = token
	u.Loaded = claim.IssuedAt
	u.Modified = true
	return nil
}

func (u *UserData) MaxSubscriptions() int64 {
	return u.Claim.Limits.Subs
}

func (u *UserData) SetMaxSubscriptions(max int64) error {
	if u.RejectEdits {
		return ErrUserIsScoped
	}
	u.Claim.Limits.Subs = max
	return u.update()
}

func (u *UserData) MaxPayload() int64 {
	return u.Claim.Limits.Payload
}

func (u *UserData) SetMaxPayload(max int64) error {
	if u.RejectEdits {
		return ErrUserIsScoped
	}
	u.Claim.Limits.Payload = max
	return u.update()
}

func (u *UserData) MaxData() int64 {
	return u.Claim.Limits.Data
}

func (u *UserData) SetMaxData(max int64) error {
	if u.RejectEdits {
		return ErrUserIsScoped
	}
	u.Claim.Limits.Data = max
	return u.update()
}

func (u *UserData) SetBearerToken(tf bool) error {
	if u.RejectEdits {
		return ErrUserIsScoped
	}
	u.Claim.BearerToken = tf
	return u.update()
}

func (u *UserData) BearerToken() bool {
	return u.Claim.BearerToken
}

func (u *UserData) ConnectionTypes() ConnectionTypes {
	v := &ConnectionTypesImpl{}
	v.rejectEdits = u.RejectEdits
	v.limits = &u.Claim.UserPermissionLimits
	v.accountData = u.AccountData
	v.userData = u
	return v
}

func (u *UserData) PubPermissions() Permissions {
	v := &PermissionsImpl{}
	v.rejectEdits = u.RejectEdits
	v.pub = true
	v.limits = &u.Claim.UserPermissionLimits
	v.accountData = u.AccountData
	v.userData = u
	return v
}

func (u *UserData) SubPermissions() Permissions {
	v := &PermissionsImpl{}
	v.rejectEdits = u.RejectEdits
	v.limits = &u.Claim.UserPermissionLimits
	v.accountData = u.AccountData
	v.userData = u
	return v
}

func (u *UserData) ResponsePermissions() ResponsePermissions {
	v := &ResponsePermissionsImpl{}
	v.rejectEdits = u.RejectEdits
	v.limits = &u.Claim.UserPermissionLimits
	v.accountData = u.AccountData
	v.userData = u
	return v
}

func (u *UserData) ConnectionSources() ConnectionSources {
	v := &ConnectionSourcesImpl{}
	v.rejectEdits = u.RejectEdits
	v.limits = &u.Claim.UserPermissionLimits
	v.accountData = u.AccountData
	v.userData = u
	return v
}

func (u *UserData) ConnectionTimes() ConnectionTimes {
	v := &ConnectionTimesImpl{}
	v.rejectEdits = u.RejectEdits
	v.accountData = u.AccountData
	v.userData = u
	v.limits = &u.Claim.UserPermissionLimits
	return v
}

func (u *UserData) Locale() string {
	return u.Claim.Limits.Locale
}

func (u *UserData) SetLocale(locale string) error {
	if u.RejectEdits {
		return ErrUserIsScoped
	}
	u.Claim.Limits.Locale = locale
	return u.update()
}

func (u *UserData) SetUserPermissionLimits(limits jwt.UserPermissionLimits) error {
	if u.RejectEdits {
		return ErrUserIsScoped
	}

	u.Claim.User.UserPermissionLimits = limits
	return u.update()
}

func (u *UserData) UserPermissionLimits() jwt.UserPermissionLimits {
	return u.Claim.User.UserPermissionLimits
}

func (u *UserData) Creds(expiry time.Duration) ([]byte, error) {
	// remember the current configuration
	token := u.Token
	if expiry > 0 {
		defer func() {
			// restore the old values
			u.Token = token
			u.Claim, _ = jwt.DecodeUserClaims(token)
		}()
		// if we have an expires, set it
		u.Claim.Expires = time.Now().Add(expiry).Unix()
		if err := u.update(); err != nil {
			return nil, err
		}
	}
	return jwt.FormatUserConfig(u.Token, u.Key.Seed)
}

func (u *UserData) Issuer() string {
	return u.Claim.Issuer
}

func (u *UserData) IssuerAccount() string {
	if u.Claim.IssuerAccount != "" {
		return u.Claim.IssuerAccount
	}
	return u.Claim.Issuer
}

func (u *UserData) Tags() Tags {
	return &UserTags{
		u: u,
	}
}

type UserTags struct {
	u *UserData
}

func (ut *UserTags) Add(tag ...string) error {
	if err := NotEmpty(tag...); err != nil {
		return err
	}
	ut.u.Claim.Tags.Add(tag...)
	return ut.u.update()
}

func (ut *UserTags) Remove(tag string) (bool, error) {
	ok := ut.u.Claim.Tags.Contains(tag)
	if ok {
		ut.u.Claim.Tags.Remove(tag)
		err := ut.u.update()
		return ok, err
	}
	return false, nil
}

func (ut *UserTags) Contains(tag string) bool {
	return ut.u.Claim.Tags.Contains(tag)
}

func (ut *UserTags) Set(tag ...string) error {
	if err := NotEmpty(tag...); err != nil {
		return err
	}
	ut.u.Claim.Tags = tag
	return ut.u.update()
}

func (ut *UserTags) All() ([]string, error) {
	return ut.u.Claim.Tags, nil
}
