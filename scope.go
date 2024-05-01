package authb

import (
	"errors"
	"time"

	"github.com/nats-io/jwt/v2"
)

type UserPermissions struct {
	rejectEdits bool
	accountData *AccountData
	userData    *UserData
	scope       *jwt.UserScope
	limits      *jwt.UserPermissionLimits
}

var ErrUserIsScoped = errors.New("user is scoped")

func (u *UserPermissions) SetUserPermissionLimits(limits jwt.UserPermissionLimits) error {
	if u.rejectEdits {
		return ErrUserIsScoped
	}
	u.limits = &limits
	if u.scope != nil {
		u.scope.Template = limits
	} else {
		u.userData.Claim.UserPermissionLimits = limits
	}
	return u.update()
}

func (u *UserPermissions) UserPermissionLimits() jwt.UserPermissionLimits {
	return *u.limits
}

func (u *UserPermissions) update() error {
	if u.scope != nil {
		u.accountData.Claim.SigningKeys[u.scope.Key] = u.scope
		if err := u.accountData.update(); err != nil {
			return err
		}
	}
	if u.userData != nil {
		return u.userData.update()
	}
	return nil
}

type ConnectionTypesImpl struct {
	UserPermissions
}

func (c *ConnectionTypesImpl) Set(connType ...string) error {
	if c.rejectEdits {
		return ErrUserIsScoped
	}
	c.limits.AllowedConnectionTypes = connType
	return c.update()
}

func (c *ConnectionTypesImpl) Types() []string {
	return c.limits.AllowedConnectionTypes
}

type PermissionsImpl struct {
	pub bool
	UserPermissions
}

func (p *PermissionsImpl) Allow() []string {
	if p.pub {
		return p.limits.Pub.Allow
	} else {
		return p.limits.Sub.Allow
	}
}

func (p *PermissionsImpl) SetAllow(subjects ...string) error {
	if p.rejectEdits {
		return ErrUserIsScoped
	}
	if p.pub {
		p.limits.Pub.Allow = subjects
	} else {
		p.limits.Sub.Allow = subjects
	}
	return p.update()
}

func (p *PermissionsImpl) Deny() []string {
	if p.pub {
		return p.limits.Pub.Deny
	} else {
		return p.limits.Sub.Deny
	}
}

func (p *PermissionsImpl) SetDeny(subjects ...string) error {
	if p.rejectEdits {
		return ErrUserIsScoped
	}
	if p.pub {
		p.limits.Pub.Deny = subjects
	} else {
		p.limits.Sub.Deny = subjects
	}
	return p.update()
}

type ResponsePermissionsImpl struct {
	UserPermissions
}

func (r *ResponsePermissionsImpl) SetMaxMessages(maxMessages int) error {
	if r.rejectEdits {
		return ErrUserIsScoped
	}
	if r.limits.Resp == nil {
		r.limits.Resp = &jwt.ResponsePermission{}
	}
	r.limits.Resp.MaxMsgs = maxMessages
	return r.update()
}

func (r *ResponsePermissionsImpl) SetExpires(expires time.Duration) error {
	if r.rejectEdits {
		return ErrUserIsScoped
	}
	if r.limits.Resp == nil {
		r.limits.Resp = &jwt.ResponsePermission{}
	}
	r.limits.Resp.Expires = expires
	return r.update()
}

func (r *ResponsePermissionsImpl) MaxMessages() int {
	if r.limits.Resp == nil {
		return 0
	}
	return r.limits.Resp.MaxMsgs
}

func (r *ResponsePermissionsImpl) Expires() time.Duration {
	if r.limits.Resp == nil {
		return time.Duration(0)
	}
	return r.limits.Resp.Expires
}

func (r *ResponsePermissionsImpl) Unset() error {
	if r.rejectEdits {
		return ErrUserIsScoped
	}
	r.limits.Resp = nil
	return r.update()
}

type ConnectionSourcesImpl struct {
	UserPermissions
}

func (c *ConnectionSourcesImpl) Sources() []string {
	v := make([]string, len(c.limits.Src))
	copy(v, c.limits.Src)
	return v
}

func (c *ConnectionSourcesImpl) Contains(p string) bool {
	return c.limits.Src.Contains(p)
}

func (c *ConnectionSourcesImpl) Add(p ...string) error {
	if c.rejectEdits {
		return ErrUserIsScoped
	}
	c.limits.Src.Add(p...)
	return c.update()
}

func (c *ConnectionSourcesImpl) Remove(p ...string) error {
	if c.rejectEdits {
		return ErrUserIsScoped
	}
	c.limits.Src.Remove(p...)
	return c.update()
}

func (c *ConnectionSourcesImpl) Set(values string) error {
	if c.rejectEdits {
		return ErrUserIsScoped
	}
	c.limits.Src.Set(values)
	return c.update()
}

type ConnectionTimesImpl struct {
	UserPermissions
}

func (t *ConnectionTimesImpl) Set(r ...TimeRange) error {
	if t.rejectEdits {
		return ErrUserIsScoped
	}
	v := make([]jwt.TimeRange, len(r))
	for i, tr := range r {
		v[i] = jwt.TimeRange{
			Start: tr.Start,
			End:   tr.End,
		}
	}
	t.limits.Times = v
	return t.update()
}

func (t *ConnectionTimesImpl) List() []TimeRange {
	v := make([]TimeRange, len(t.limits.Times))
	for i, tr := range t.limits.Times {
		v[i] = TimeRange{
			Start: tr.Start,
			End:   tr.End,
		}
	}
	return v
}

func (u *UserPermissions) MaxSubscriptions() int64 {
	return u.limits.Subs
}

func (u *UserPermissions) SetMaxSubscriptions(max int64) error {
	if u.rejectEdits {
		return ErrUserIsScoped
	}
	u.limits.Subs = max
	return u.update()
}

func (u *UserPermissions) MaxPayload() int64 {
	return u.limits.Payload
}

func (u *UserPermissions) SetMaxPayload(max int64) error {
	if u.rejectEdits {
		return ErrUserIsScoped
	}
	u.limits.Payload = max
	return u.update()
}

func (u *UserPermissions) MaxData() int64 {
	return u.limits.Data
}

func (u *UserPermissions) SetMaxData(max int64) error {
	if u.rejectEdits {
		return ErrUserIsScoped
	}
	u.limits.Data = max
	return u.update()
}

func (u *UserPermissions) SetBearerToken(tf bool) error {
	if u.rejectEdits {
		return ErrUserIsScoped
	}
	u.limits.BearerToken = tf
	return u.update()
}

func (u *UserPermissions) BearerToken() bool {
	return u.limits.BearerToken
}

func (u *UserPermissions) ConnectionTypes() ConnectionTypes {
	v := &ConnectionTypesImpl{}
	v.scope = u.scope
	v.limits = u.limits
	v.accountData = u.accountData
	return v
}

func (u *UserPermissions) PubPermissions() Permissions {
	v := &PermissionsImpl{pub: true}
	v.scope = u.scope
	v.limits = u.limits
	v.accountData = u.accountData
	return v
}

func (u *UserPermissions) SubPermissions() Permissions {
	v := &PermissionsImpl{}
	v.scope = u.scope
	v.limits = u.limits
	v.accountData = u.accountData
	return v
}

func (u *UserPermissions) ResponsePermissions() ResponsePermissions {
	v := &ResponsePermissionsImpl{}
	v.scope = u.scope
	v.limits = u.limits
	v.accountData = u.accountData
	return v
}

func (u *UserPermissions) ConnectionSources() ConnectionSources {
	v := &ConnectionSourcesImpl{}
	v.scope = u.scope
	v.limits = u.limits
	v.accountData = u.accountData
	return v
}

func (u *UserPermissions) ConnectionTimes() ConnectionTimes {
	v := &ConnectionTimesImpl{}
	v.scope = u.scope
	v.limits = u.limits
	v.accountData = u.accountData
	return v
}

func (u *UserPermissions) Locale() string {
	return u.limits.Locale
}

func (u *UserPermissions) SetLocale(locale string) error {
	if u.rejectEdits {
		return ErrUserIsScoped
	}
	u.limits.Locale = locale
	return u.update()
}

type ScopeImpl struct {
	UserPermissions
}

func toScopeLimits(account *AccountData, scope *jwt.UserScope) ScopeLimits {
	v := &ScopeImpl{}
	v.scope = scope
	v.accountData = account
	v.limits = &scope.Template
	return v
}

func (s *ScopeImpl) Key() string {
	return s.scope.Key
}

func (s *ScopeImpl) Role() string {
	return s.scope.Role
}

func (s *ScopeImpl) SetRole(name string) error {
	s.scope.Role = name
	return s.update()
}

func (s *ScopeImpl) Description() string {
	return s.scope.Description
}

func (s *ScopeImpl) SetDescription(description string) error {
	s.scope.Description = description
	return s.update()
}

func (s *ScopeImpl) update() error {
	s.accountData.Claim.SigningKeys[s.scope.Key] = s.scope
	return s.accountData.update()
}
