package tests

import (
	"fmt"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/nats-io/jwt/v2"
	authb "github.com/synadia-io/jwt-auth-builder.go"
)

func (t *ProviderSuite) Test_AccountsCrud() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)

	accounts := o.Accounts().List()
	t.NoError(err)
	t.Equal(0, len(accounts))

	a, err := o.Accounts().Add("A")
	t.NoError(err)
	b, err := o.Accounts().Add("B")
	t.NoError(err)

	x, err := o.Accounts().Get("X")
	t.ErrorIs(err, authb.ErrNotFound)
	t.Nil(x)

	x, err = o.Accounts().Get("A")
	t.NoError(err)
	t.NotNil(x)
	t.Equal("A", x.Name())

	accounts = o.Accounts().List()
	t.NoError(err)
	t.Equal(2, len(accounts))
	t.Contains(accounts, a)
	t.Contains(accounts, b)

	t.NoError(o.Accounts().Delete("A"))
	accounts = o.Accounts().List()
	t.NoError(err)
	t.Equal(1, len(accounts))
	t.Contains(accounts, b)

	t.NoError(auth.Commit())
	t.True(t.Store.AccountExists("O", "B"))
	t.False(t.Store.AccountExists("O", "A"))
}

func (t *ProviderSuite) Test_AccountsBasics() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)

	a, err := o.Accounts().Add("A")
	t.NoError(err)

	ai := a.(*authb.AccountData)
	t.Equal(ai.Claim.Subject, a.Subject())
	t.Equal(o.Subject(), a.Issuer())

	acct, err := authb.NewAccountFromJWT(a.JWT())
	t.NoError(err)
	t.Equal(acct.Subject(), a.Subject())
	err = acct.SetExpiry(time.Now().Unix())
	t.Equal(err, fmt.Errorf("account is read-only"))
}

func (t *ProviderSuite) Test_AccountLimitsSetter() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)

	a, err := o.Accounts().Add("A")
	t.NoError(err)

	t.NoError(a.Limits().SetMaxExports(10))
	t.Equal(a.Limits().MaxExports(), int64(10))
	t.Equal(a.Limits().MaxImports(), int64(-1))

	type operatorLimitsManager interface {
		OperatorLimits() jwt.OperatorLimits
		SetOperatorLimits(limits jwt.OperatorLimits) error
	}

	al := a.Limits().(operatorLimitsManager).OperatorLimits()
	t.Equal(al.Exports, int64(10))

	al.Exports = 20
	al.Imports = 10
	t.NoError(a.Limits().(operatorLimitsManager).SetOperatorLimits(al))
	t.Equal(a.Limits().MaxExports(), int64(20))
	t.Equal(a.Limits().MaxImports(), int64(10))
}

func (t *ProviderSuite) Test_UserPermissionLimitsSetter() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)

	a, err := o.Accounts().Add("A")
	t.NoError(err)

	user, err := a.Users().Add("BOB", "")
	t.NoError(err)

	t.Equal(user.MaxSubscriptions(), int64(-1))
	t.Empty(user.PubPermissions().Allow())

	type userLimitsManager interface {
		UserPermissionLimits() jwt.UserPermissionLimits
		SetUserPermissionLimits(limits jwt.UserPermissionLimits) error
	}

	limits := jwt.UserPermissionLimits{}
	limits.Permissions.Pub.Allow = []string{"test.>"}
	limits.NatsLimits.Subs = 1000

	err = user.(userLimitsManager).SetUserPermissionLimits(limits)
	t.NoError(err)

	t.Equal(user.MaxSubscriptions(), int64(1000))
	t.Equal(user.PubPermissions().Allow(), []string{"test.>"})
}

func (t *ProviderSuite) Test_ScopedUserPermissionLimitsSetter() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)

	a, err := o.Accounts().Add("A")
	t.NoError(err)

	scope, err := a.ScopedSigningKeys().AddScope("test")
	t.NoError(err)

	user, err := a.Users().Add("BOB", scope.Key())
	t.NoError(err)

	t.Equal(scope.MaxSubscriptions(), int64(-1))
	t.Empty(scope.PubPermissions().Allow())

	limits := jwt.UserPermissionLimits{}
	limits.Permissions.Pub.Allow = []string{"test.>"}
	limits.NatsLimits.Subs = 1000

	type userLimitsManager interface {
		UserPermissionLimits() jwt.UserPermissionLimits
		SetUserPermissionLimits(limits jwt.UserPermissionLimits) error
	}

	err = user.(userLimitsManager).SetUserPermissionLimits(limits)
	t.Errorf(err, "user is scoped")

	err = scope.(userLimitsManager).SetUserPermissionLimits(limits)
	t.NoError(err)

	t.Equal(scope.MaxSubscriptions(), int64(1000))
	t.Equal(scope.PubPermissions().Allow(), []string{"test.>"})
}

func (t *ProviderSuite) Test_ScopedOrNot() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)

	a, err := o.Accounts().Add("A")
	t.NoError(err)

	scope, err := a.ScopedSigningKeys().AddScope("test")
	t.NoError(err)

	lim, err := a.ScopedSigningKeys().GetScope(scope.Key())
	t.NoError(err)
	t.NotNil(lim)

	pk, err := a.ScopedSigningKeys().Add()
	t.NoError(err)

	lim, err = a.ScopedSigningKeys().GetScope(pk)
	t.Error(err)
	t.Nil(lim)

	ok, scoped := a.ScopedSigningKeys().Contains(pk)
	t.True(ok)
	t.False(scoped)
}

func setupTestWithOperatorAndAccount(p *ProviderSuite) (authb.Auth, authb.Operator, authb.Account) {
	auth, err := authb.NewAuth(p.Provider)
	p.NoError(err)
	o, err := auth.Operators().Add("O")
	p.NoError(err)
	p.NoError(auth.Commit())

	a, err := o.Accounts().Add("A")
	p.NoError(err)
	return auth, o, a
}

func (t *ProviderSuite) Test_ScopedPermissionsMaxSubs() {
	auth, _, a := setupTestWithOperatorAndAccount(t)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	t.NoError(err)
	t.NoError(s.SetMaxSubscriptions(10))
	t.Equal(int64(10), s.MaxSubscriptions())
	t.NoError(auth.Commit())

	t.NoError(auth.Reload())

	o, err := auth.Operators().Get("O")
	t.NoError(err)

	a, err = o.Accounts().Get("A")
	t.NoError(err)

	scopes, err := a.ScopedSigningKeys().GetScopeByRole("admin")
	t.NoError(err)
	t.Len(scopes, 1)
	t.Equal(int64(10), scopes[0].MaxSubscriptions())
}

func (t *ProviderSuite) Test_ScopedPermissionsMaxPayload() {
	auth, _, a := setupTestWithOperatorAndAccount(t)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	t.NoError(err)
	t.NoError(s.SetMaxPayload(101))
	t.Equal(int64(101), s.MaxPayload())
	t.NoError(auth.Commit())

	t.NoError(auth.Reload())

	o, err := auth.Operators().Get("O")
	t.NoError(err)

	a, err = o.Accounts().Get("A")
	t.NoError(err)

	scopes, err := a.ScopedSigningKeys().GetScopeByRole("admin")
	t.NoError(err)
	t.Equal(int64(101), scopes[0].MaxPayload())
}

func (t *ProviderSuite) Test_ScopedPermissionsMaxData() {
	auth, _, a := setupTestWithOperatorAndAccount(t)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	t.NoError(err)
	t.NoError(s.SetMaxData(4123))
	t.Equal(int64(4123), s.MaxData())
	t.NoError(auth.Commit())

	t.NoError(auth.Reload())

	o, err := auth.Operators().Get("O")
	t.NoError(err)

	a, err = o.Accounts().Get("A")
	t.NoError(err)
	t.NotNil(a)

	scopes, err := a.ScopedSigningKeys().GetScopeByRole("admin")
	t.NoError(err)
	t.Equal(int64(4123), scopes[0].MaxData())
}

func (t *ProviderSuite) Test_ScopedPermissionsBearerToken() {
	auth, _, a := setupTestWithOperatorAndAccount(t)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	t.NoError(err)
	t.NoError(s.SetBearerToken(true))
	t.True(s.BearerToken())
	t.NoError(auth.Commit())

	t.NoError(auth.Reload())

	o, err := auth.Operators().Get("O")
	t.NoError(err)

	a, err = o.Accounts().Get("A")
	t.NoError(err)

	scopes, err := a.ScopedSigningKeys().GetScopeByRole("admin")
	t.NoError(err)
	t.True(scopes[0].BearerToken())
}

func (t *ProviderSuite) Test_ScopedPermissionsConnectionTypes() {
	auth, _, a := setupTestWithOperatorAndAccount(t)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	t.NoError(err)
	types := s.ConnectionTypes()
	t.NoError(types.Set("websocket"))
	t.Contains(types.Types(), "websocket")
	t.NoError(auth.Commit())

	t.NoError(auth.Reload())

	o, err := auth.Operators().Get("O")
	t.NoError(err)

	a, err = o.Accounts().Get("A")
	t.NoError(err)

	scopes, err := a.ScopedSigningKeys().GetScopeByRole("admin")
	t.NoError(err)
	t.Len(scopes, 1)
	types = scopes[0].ConnectionTypes()
	t.Contains(types.Types(), "websocket")
}

func (t *ProviderSuite) Test_ScopedPermissionsConnectionSources() {
	auth, _, a := setupTestWithOperatorAndAccount(t)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	t.NoError(err)
	sources := s.ConnectionSources()
	t.NoError(sources.Add("192.0.2.0/24"))
	t.Contains(sources.Sources(), "192.0.2.0/24")
	t.NoError(auth.Commit())

	t.NoError(auth.Reload())

	o, err := auth.Operators().Get("O")
	t.NoError(err)

	a, err = o.Accounts().Get("A")
	t.NoError(err)

	scopes, err := a.ScopedSigningKeys().GetScopeByRole("admin")
	t.NoError(err)
	t.Len(scopes, 1)
	sources = scopes[0].ConnectionSources()
	t.Contains(sources.Sources(), "192.0.2.0/24")
}

func (t *ProviderSuite) Test_ScopedPermissionsConnectionTimes() {
	auth, _, a := setupTestWithOperatorAndAccount(t)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	t.NoError(err)
	times := s.ConnectionTimes()
	t.NoError(times.Set(authb.TimeRange{Start: "08:00:00", End: "12:00:00"}))
	t.Len(times.List(), 1)
	t.NoError(auth.Commit())

	t.NoError(auth.Reload())

	o, err := auth.Operators().Get("O")
	t.NoError(err)

	a, err = o.Accounts().Get("A")
	t.NoError(err)

	scopes, err := a.ScopedSigningKeys().GetScopeByRole("admin")
	t.NoError(err)
	t.Len(scopes, 1)
	times = scopes[0].ConnectionTimes()
	t.Len(times.List(), 1)
	t.Equal(times.List()[0].Start, "08:00:00")
	t.Equal(times.List()[0].End, "12:00:00")
}

func (t *ProviderSuite) Test_ScopedPermissionsLocale() {
	auth, _, a := setupTestWithOperatorAndAccount(t)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	t.NoError(err)
	t.NoError(s.SetLocale("en_US"))
	t.NoError(auth.Commit())

	t.NoError(auth.Reload())

	o, err := auth.Operators().Get("O")
	t.NoError(err)

	a, err = o.Accounts().Get("A")
	t.NoError(err)

	scopes, err := a.ScopedSigningKeys().GetScopeByRole("admin")
	t.NoError(err)
	t.Len(scopes, 1)
	t.Equal("en_US", scopes[0].Locale())
}

func (t *ProviderSuite) Test_ScopedPermissionsSubject() {
	auth, _, a := setupTestWithOperatorAndAccount(t)

	admin, err := a.ScopedSigningKeys().AddScope("admin")
	t.NoError(err)
	t.NotNil(admin)

	pubPerms := admin.PubPermissions()
	t.NoError(pubPerms.SetAllow("foo", "bar"))
	t.NoError(pubPerms.SetDeny("baz"))

	subPerms := admin.SubPermissions()
	t.NoError(subPerms.SetAllow("foo", "bar"))
	t.NoError(subPerms.SetDeny("baz"))

	respPerms := admin.ResponsePermissions()
	t.NoError(respPerms.SetMaxMessages(10))
	t.NoError(respPerms.SetExpires(time.Second))

	t.NoError(auth.Reload())

	scopes, err := a.ScopedSigningKeys().GetScopeByRole("admin")
	t.NoError(err)
	t.Len(scopes, 1)
	admin = scopes[0]

	t.Contains(admin.PubPermissions().Allow(), "foo")
	t.Contains(admin.PubPermissions().Allow(), "bar")
	t.Contains(admin.PubPermissions().Deny(), "baz")

	t.Contains(admin.SubPermissions().Allow(), "foo")
	t.Contains(admin.SubPermissions().Allow(), "bar")
	t.Contains(admin.SubPermissions().Deny(), "baz")

	perm := admin.ResponsePermissions()
	t.NotNil(perm)
	t.Equal(10, perm.MaxMessages())
	t.Equal(time.Second, perm.Expires())
}

func (t *ProviderSuite) Test_ScopeRotation() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)

	a, err := o.Accounts().Add("A")
	t.NoError(err)

	scope, err := a.ScopedSigningKeys().AddScope("admin")
	t.NoError(err)
	t.NotNil(scope)
	scope2, err := a.ScopedSigningKeys().GetScope(scope.Key())
	t.NoError(err)
	t.NotNil(scope2)

	key, err := a.ScopedSigningKeys().Rotate(scope.Key())
	t.NoError(err)
	t.NotEmpty(key)

	scope2, err = a.ScopedSigningKeys().GetScope(scope.Key())
	t.ErrorIs(err, authb.ErrNotFound)
	t.Nil(scope2)

	scope2, err = a.ScopedSigningKeys().GetScope(key)
	t.NoError(err)
	t.NotNil(scope2)

	ok, err := a.ScopedSigningKeys().Delete(key)
	t.NoError(err)
	t.True(ok)

	scope2, err = a.ScopedSigningKeys().GetScope(key)
	t.ErrorIs(err, authb.ErrNotFound)
	t.Nil(scope2)
}

func (t *ProviderSuite) Test_ScopeDeletion() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)

	a, err := o.Accounts().Add("A")
	t.NoError(err)

	scope, err := a.ScopedSigningKeys().AddScope("admin")
	t.NoError(err)
	t.NotNil(scope)
	key := scope.Key()

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	o, err = auth.Operators().Get("O")
	t.NoError(err)
	a, err = o.Accounts().Get("A")
	t.NoError(err)
	ok, err := a.ScopedSigningKeys().Delete(key)
	t.NoError(err)
	t.True(ok)

	t.Empty(a.ScopedSigningKeys().ListRoles())
	t.Empty(a.ScopedSigningKeys().List())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	o, err = auth.Operators().Get("O")
	t.NoError(err)
	a, err = o.Accounts().Get("A")
	t.NoError(err)

	t.Empty(a.ScopedSigningKeys().List())
	t.Empty(a.ScopedSigningKeys().ListRoles())
}

func (t *ProviderSuite) Test_SigningKeyRotation() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)

	a, err := o.Accounts().Add("A")
	t.NoError(err)

	sk, err := a.ScopedSigningKeys().Add()
	t.NoError(err)
	t.NotEmpty(sk)

	scope, err := a.ScopedSigningKeys().GetScope(sk)
	t.ErrorIs(err, authb.ErrNotFound)
	t.Nil(scope)

	u, err := a.Users().Add("U", sk)
	t.NoError(err)
	t.NotNil(u)

	t.Equal(sk, u.Issuer())

	key, err := a.ScopedSigningKeys().Rotate(sk)
	t.NoError(err)
	t.NotEmpty(key)

	t.Equal(key, u.Issuer())
}

func (t *ProviderSuite) Test_DeleteTier() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	t.False(a.Limits().JetStream().IsJetStreamEnabled())

	tier, err := a.Limits().JetStream().Add(3)
	t.NoError(err)
	t.False(a.Limits().JetStream().IsJetStreamEnabled())

	t.NoError(tier.SetUnlimited())
	t.True(a.Limits().JetStream().IsJetStreamEnabled())

	ok, err := a.Limits().JetStream().Delete(3)
	t.NoError(err)
	t.True(ok)
	t.False(a.Limits().JetStream().IsJetStreamEnabled())

	tier, err = a.Limits().JetStream().Add(5)
	t.NoError(err)
	t.NoError(tier.SetUnlimited())
	t.True(a.Limits().JetStream().IsJetStreamEnabled())

	t.NoError(tier.Delete())
	t.False(a.Limits().JetStream().IsJetStreamEnabled())
}

func (t *ProviderSuite) Test_AccountLimits() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	a, err := o.Accounts().Add("A")
	t.NoError(err)

	t.Equal(int64(-1), a.Limits().MaxData())
	t.Equal(int64(-1), a.Limits().MaxSubscriptions())
	t.Equal(int64(-1), a.Limits().MaxPayload())
	t.Equal(int64(-1), a.Limits().MaxConnections())
	t.Equal(int64(-1), a.Limits().MaxLeafNodeConnections())
	t.Equal(int64(-1), a.Limits().MaxImports())
	t.Equal(int64(-1), a.Limits().MaxExports())
	t.True(a.Limits().AllowWildcardExports())
	t.False(a.Limits().DisallowBearerTokens())

	t.NoError(a.Limits().SetMaxData(100))
	t.NoError(a.Limits().SetMaxSubscriptions(1_000))
	t.NoError(a.Limits().SetMaxPayload(1_0000))
	t.NoError(a.Limits().SetMaxConnections(3))
	t.NoError(a.Limits().SetMaxLeafNodeConnections(30))
	t.NoError(a.Limits().SetMaxImports(300))
	t.NoError(a.Limits().SetMaxExports(3_000))
	t.NoError(a.Limits().SetAllowWildcardExports(false))
	t.NoError(a.Limits().SetDisallowBearerTokens(true))
	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	t.Equal(int64(100), a.Limits().MaxData())
	t.Equal(int64(1_000), a.Limits().MaxSubscriptions())
	t.Equal(int64(10_000), a.Limits().MaxPayload())
	t.Equal(int64(3), a.Limits().MaxConnections())
	t.Equal(int64(30), a.Limits().MaxLeafNodeConnections())
	t.Equal(int64(300), a.Limits().MaxImports())
	t.Equal(int64(3_000), a.Limits().MaxExports())
	t.False(a.Limits().AllowWildcardExports())
	t.True(a.Limits().DisallowBearerTokens())
}

func (t *ProviderSuite) testTier(auth authb.Auth, account authb.Account, tier int8) {
	var err error

	js := account.Limits().JetStream()
	t.False(js.IsJetStreamEnabled())
	lim, err := js.Get(tier)
	t.NoError(err)
	if tier == 0 {
		t.NotNil(lim)
	} else {
		t.Nil(lim)
		lim, err = js.Add(tier)
		t.NoError(err)
	}
	ok, err := lim.IsUnlimited()
	t.NoError(err)
	t.False(ok)

	num, err := lim.MaxMemoryStorage()
	t.NoError(err)
	t.Equal(int64(0), num)

	num, err = lim.MaxDiskStorage()
	t.NoError(err)
	t.Equal(int64(0), num)

	num, err = lim.MaxMemoryStreamSize()
	t.NoError(err)
	t.Equal(int64(0), num)

	num, err = lim.MaxDiskStreamSize()
	t.NoError(err)
	t.Equal(int64(0), num)

	tf, err := lim.MaxStreamSizeRequired()
	t.NoError(err)
	t.False(tf)

	num, err = lim.MaxStreams()
	t.NoError(err)
	t.Equal(int64(0), num)

	num, err = lim.MaxConsumers()
	t.NoError(err)
	t.Equal(int64(0), num)

	num, err = lim.MaxAckPending()
	t.NoError(err)
	t.Equal(int64(0), num)

	t.NoError(lim.SetMaxDiskStorage(1000))
	t.NoError(lim.SetMaxMemoryStorage(2000))
	t.NoError(lim.SetMaxMemoryStreamSize(4000))
	t.NoError(lim.SetMaxDiskStreamSize(8000))
	t.NoError(lim.SetMaxStreamSizeRequired(true))
	t.NoError(lim.SetMaxStreams(5))
	t.NoError(lim.SetMaxConsumers(50))
	t.NoError(lim.SetMaxAckPending(22))

	tf, err = lim.IsUnlimited()
	t.NoError(err)
	t.False(tf)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	lim, err = js.Get(tier)
	t.NoError(err)
	t.NotNil(lim)

	tf, err = lim.IsUnlimited()
	t.NoError(err)
	t.False(tf)

	num, err = lim.MaxDiskStorage()
	t.NoError(err)
	t.Equal(int64(1000), num)

	num, err = lim.MaxMemoryStorage()
	t.NoError(err)
	t.Equal(int64(2000), num)

	num, err = lim.MaxMemoryStreamSize()
	t.NoError(err)
	t.Equal(int64(4000), num)

	num, err = lim.MaxDiskStreamSize()
	t.NoError(err)
	t.Equal(int64(8000), num)

	tf, err = lim.MaxStreamSizeRequired()
	t.NoError(err)
	t.True(tf)

	num, err = lim.MaxStreams()
	t.NoError(err)
	t.Equal(int64(5), num)

	num, err = lim.MaxConsumers()
	t.NoError(err)
	t.Equal(int64(50), num)

	num, err = lim.MaxAckPending()
	t.NoError(err)
	t.Equal(int64(22), num)

	t.NoError(lim.SetUnlimited())
	tf, err = lim.IsUnlimited()
	t.NoError(err)
	t.True(tf)
}

func (t *ProviderSuite) Test_AccountJetStreamLimits() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	a, err := o.Accounts().Add("A")
	t.NoError(err)
	t.testTier(auth, a, 0)
	b, err := o.Accounts().Add("B")
	t.NoError(err)
	t.testTier(auth, b, 1)
}

func (t *ProviderSuite) Test_AccountSkUpdate() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	operators := auth.Operators()
	t.Empty(operators.List())

	o, err := operators.Add("O")
	t.NoError(err)
	t.NotNil(o)

	a, err := o.Accounts().Add("A")
	t.NoError(err)
	t.NotNil(a)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	o, err = operators.Get("O")
	t.NoError(err)

	a, err = o.Accounts().Get("A")
	t.NoError(err)

	k, err := a.ScopedSigningKeys().Add()
	t.NoError(err)
	t.NotEmpty(k)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	o, err = operators.Get("O")
	t.NoError(err)
	a, err = o.Accounts().Get("A")
	t.NoError(err)
	exists, isScope := a.ScopedSigningKeys().Contains(k)
	t.True(exists)
	t.False(isScope)
}

func (t *ProviderSuite) Test_AccountSigningKeys() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	operators := auth.Operators()
	t.Empty(operators.List())

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	var keys []string
	k, err := a.ScopedSigningKeys().Add()
	t.NoError(err)
	t.NotEmpty(k)
	keys = append(keys, k)

	sl, err := a.ScopedSigningKeys().AddScope("admin")
	t.NoError(err)
	t.NotNil(sl)
	keys = append(keys, sl.Key())
	keys2 := a.ScopedSigningKeys().List()
	for _, k := range keys {
		t.Contains(keys2, k)
	}

	roles := a.ScopedSigningKeys().ListRoles()
	t.NotNil(roles)
	t.Len(roles, 1)
	t.Contains(roles, "admin")
}

func (t *ProviderSuite) Test_AccountRevocationEmpty() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)
	r := a.Revocations()
	t.NotNil(r)
	t.Len(r.List(), 0)
}

func (t *ProviderSuite) Test_AccountRevokesRejectNonUserKey() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)
	revocations := a.Revocations()
	t.NotNil(revocations)
	t.Len(revocations.List(), 0)

	err = revocations.Add(t.AccountKey().Public, time.Now())
	t.Error(err)
}

func (t *ProviderSuite) Test_AccountRevokeUser() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)
	revocations := a.Revocations()
	t.NotNil(revocations)
	t.Len(revocations.List(), 0)

	uk := t.UserKey().Public
	err = revocations.Add(uk, time.Now())
	t.NoError(err)

	revokes := revocations.List()
	t.Len(revokes, 1)
	t.Equal(uk, revokes[0].PublicKey())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	a = t.GetAccount(auth, "O", "A")
	t.NotNil(a)
	t.True(a.Revocations().Contains(uk))

	ok, err := a.Revocations().Delete(uk)
	t.NoError(err)
	t.True(ok)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	a = t.GetAccount(auth, "O", "A")
	t.NotNil(a)
	t.False(a.Revocations().Contains(uk))
}

func (t *ProviderSuite) Test_AccountRevokeWildcard() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)
	revocations := a.Revocations()
	t.NotNil(revocations)
	t.Len(revocations.List(), 0)

	err = revocations.Add("*", time.Now())
	t.NoError(err)

	revokes := revocations.List()
	t.Len(revokes, 1)
	t.Equal("*", revokes[0].PublicKey())
}

func (t *ProviderSuite) Test_TracingContext() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	t.Nil(a.GetTracingContext())
	t.NoError(a.SetTracingContext(&authb.TracingContext{
		Destination: "tracing.here",
		Sampling:    100,
	}))
	tc := a.GetTracingContext()
	t.NotNil(tc)
	t.Equal("tracing.here", tc.Destination)
	t.Equal(100, tc.Sampling)

	t.NoError(a.SetTracingContext(nil))
	t.Nil(a.GetTracingContext())
}

func (t *ProviderSuite) Test_ExternalAuthorization() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	external := t.MaybeCreate(auth, "O", "AUTH")
	t.NotNil(external)
	u, err := external.Users().Add("service", external.Subject())
	t.NoError(err)

	curve, err := authb.KeyFor(nkeys.PrefixByteCurve)
	t.NoError(err)

	users, accounts, key := external.ExternalAuthorization()
	t.Empty(users)
	t.Empty(accounts)
	t.Empty(key)

	t.NoError(external.SetExternalAuthorizationUser([]authb.User{u}, []authb.Account{a}, curve.Public))

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	external = t.GetAccount(auth, "O", "AUTH")
	t.NotNil(external)

	users, accounts, key = external.ExternalAuthorization()
	t.Equal(users, []string{u.Subject()})
	t.Equal(accounts, []string{a.Subject()})
	t.Equal(key, curve.Public)

	t.NoError(external.SetExternalAuthorizationUser(nil, nil, ""))
	users, accounts, key = external.ExternalAuthorization()
	t.Nil(users)
	t.Nil(accounts)
	t.Empty(key)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	external = t.GetAccount(auth, "O", "AUTH")
	t.NotNil(external)
	users, accounts, key = external.ExternalAuthorization()
	t.Nil(users)
	t.Nil(accounts)
	t.Empty(key)
}

func (t *ProviderSuite) Test_AccountSignClaim() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	a, err := o.Accounts().Add("A")
	t.NoError(err)
	sk, err := a.ScopedSigningKeys().Add()
	t.NoError(err)
	scope, err := a.ScopedSigningKeys().AddScope("sentinel")
	t.NoError(err)
	t.NoError(scope.SubPermissions().SetDeny(">"))
	t.NoError(scope.PubPermissions().SetDeny(">"))

	gc := jwt.NewGenericClaims(a.Subject())
	gc.Name = "t"
	gc.Data["testing"] = "foo"
	token, err := a.IssueClaim(gc, "")
	t.NoError(err)
	gc, err = jwt.DecodeGeneric(token)
	t.NoError(err)
	t.Equal(gc.Issuer, a.Subject())
	_, err = a.IssueClaim(gc, scope.Key())
	t.Error(err)
	t.Contains(err.Error(), "scoped keys can only issue user claims")

	ukey, err := auth.NewKey(nkeys.PrefixByteUser)
	t.NoError(err)
	token, err = a.IssueClaim(jwt.NewUserClaims(ukey.Public), "")
	t.NoError(err)
	u, err := jwt.DecodeUserClaims(token)
	t.NoError(err)
	t.Equal(u.Issuer, a.Subject())

	// signing key keeps perms
	uc := jwt.NewUserClaims(ukey.Public)
	uc.UserPermissionLimits = jwt.UserPermissionLimits{}
	uc.UserPermissionLimits.Permissions.Pub.Allow.Add("foo")
	token, err = a.IssueClaim(uc, sk)
	t.NoError(err)
	u, err = jwt.DecodeUserClaims(token)
	t.NoError(err)
	t.Equal(u.Issuer, sk)
	t.Equal(u.IssuerAccount, a.Subject())
	t.True(u.UserPermissionLimits.Permissions.Pub.Allow.Contains("foo"))

	// scoped deletes pub perms
	token, err = a.IssueClaim(jwt.NewUserClaims(ukey.Public), scope.Key())
	t.NoError(err)
	u, err = jwt.DecodeUserClaims(token)
	t.NoError(err)
	t.False(u.UserPermissionLimits.Permissions.Pub.Allow.Contains("foo"))

	ar := jwt.NewAuthorizationRequestClaims(ukey.Public)
	_, err = a.IssueClaim(ar, "")
	t.Error(err)
	t.Contains(err.Error(), "accounts cannot issue authorization")

	_, err = a.IssueClaim(jwt.NewGenericClaims(ukey.Public), "")
	t.NoError(err)

	_, err = a.IssueClaim(jwt.NewGenericClaims(ukey.Public), scope.Key())
	t.Error(err)
	t.Contains(err.Error(), "scoped keys can only issue user claims")

	_, err = a.IssueClaim(jwt.NewOperatorClaims(o.Subject()), "")
	t.Error(err)
	t.Contains(err.Error(), "accounts cannot issue operator claims")

	ac, err := jwt.DecodeAccountClaims(a.JWT())
	t.NoError(err)
	_, err = a.IssueClaim(ac, "")
	t.NoError(err)
	_, err = a.IssueClaim(ac, scope.Key())
	t.Error(err)
	t.Contains(err.Error(), "accounts can only self-sign")
}
