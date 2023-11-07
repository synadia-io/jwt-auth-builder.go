package tests

import (
	"github.com/stretchr/testify/require"
	authb "github.com/synadia-io/jwt-auth-builder.go"
	"time"
)

func (suite *ProviderSuite) Test_AccountsCrud() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)

	accounts := o.Accounts().List()
	require.Nil(t, err)
	require.Equal(t, 0, len(accounts))

	a, err := o.Accounts().Add("A")
	require.NoError(t, err)
	b, err := o.Accounts().Add("B")
	require.NoError(t, err)

	x := o.Accounts().Get("X")
	require.Nil(t, err)
	require.Nil(t, x)

	x = o.Accounts().Get("A")
	require.Nil(t, err)
	require.NotNil(t, x)
	require.Equal(t, "A", x.Name())

	accounts = o.Accounts().List()
	require.Nil(t, err)
	require.Equal(t, 2, len(accounts))
	require.Contains(t, accounts, a)
	require.Contains(t, accounts, b)

	require.NoError(t, o.Accounts().Delete("A"))
	accounts = o.Accounts().List()
	require.Nil(t, err)
	require.Equal(t, 1, len(accounts))
	require.Contains(t, accounts, b)

	require.NoError(t, auth.Commit())
	require.True(t, suite.Store.AccountExists("O", "B"))
	require.False(t, suite.Store.AccountExists("O", "A"))
}

func (suite *ProviderSuite) Test_AccountsBasics() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)

	a, err := o.Accounts().Add("A")
	require.NoError(t, err)

	ai := a.(*authb.AccountData)
	require.Equal(t, ai.Claim.Subject, a.Subject())
	require.Equal(t, o.Subject(), a.Issuer())
}

func setupTestWithOperatorAndAccount(p *ProviderSuite) (authb.Auth, authb.Operator, authb.Account) {
	t := p.T()
	auth, err := authb.NewAuth(p.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	require.NoError(t, auth.Commit())

	a, err := o.Accounts().Add("A")
	require.NoError(t, err)
	return auth, o, a
}

func (suite *ProviderSuite) Test_ScopedPermissionsMaxSubs() {
	t := suite.T()
	auth, _, a := setupTestWithOperatorAndAccount(suite)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	require.NoError(t, err)
	require.NoError(t, s.SetMaxSubscriptions(10))
	require.Equal(t, int64(10), s.MaxSubscriptions())
	require.NoError(t, auth.Commit())

	require.NoError(t, auth.Reload())

	o := auth.Operators().Get("O")
	require.NoError(t, err)
	require.NotNil(t, o)

	a = o.Accounts().Get("A")
	require.NoError(t, err)
	require.NotNil(t, a)

	s = a.ScopedSigningKeys().GetScopeByRole("admin")
	require.NotNil(t, s)
	require.Equal(t, int64(10), s.MaxSubscriptions())
}

func (suite *ProviderSuite) Test_ScopedPermissionsMaxPayload() {
	t := suite.T()
	auth, _, a := setupTestWithOperatorAndAccount(suite)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	require.NoError(t, err)
	require.NoError(t, s.SetMaxPayload(101))
	require.Equal(t, int64(101), s.MaxPayload())
	require.NoError(t, auth.Commit())

	require.NoError(t, auth.Reload())

	o := auth.Operators().Get("O")
	require.NoError(t, err)
	require.NotNil(t, o)

	a = o.Accounts().Get("A")
	require.NoError(t, err)
	require.NotNil(t, a)

	s = a.ScopedSigningKeys().GetScopeByRole("admin")
	require.NotNil(t, s)
	require.Equal(t, int64(101), s.MaxPayload())
}

func (suite *ProviderSuite) Test_ScopedPermissionsMaxData() {
	t := suite.T()
	auth, _, a := setupTestWithOperatorAndAccount(suite)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	require.NoError(t, err)
	require.NoError(t, s.SetMaxData(4123))
	require.Equal(t, int64(4123), s.MaxData())
	require.NoError(t, auth.Commit())

	require.NoError(t, auth.Reload())

	o := auth.Operators().Get("O")
	require.NoError(t, err)
	require.NotNil(t, o)

	a = o.Accounts().Get("A")
	require.NoError(t, err)
	require.NotNil(t, a)

	s = a.ScopedSigningKeys().GetScopeByRole("admin")
	require.NotNil(t, s)
	require.Equal(t, int64(4123), s.MaxData())
}

func (suite *ProviderSuite) Test_ScopedPermissionsBearerToken() {
	t := suite.T()
	auth, _, a := setupTestWithOperatorAndAccount(suite)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	require.NoError(t, err)
	require.NoError(t, s.SetBearerToken(true))
	require.True(t, s.BearerToken())
	require.NoError(t, auth.Commit())

	require.NoError(t, auth.Reload())

	o := auth.Operators().Get("O")
	require.NoError(t, err)
	require.NotNil(t, o)

	a = o.Accounts().Get("A")
	require.NoError(t, err)
	require.NotNil(t, a)

	s = a.ScopedSigningKeys().GetScopeByRole("admin")
	require.NotNil(t, s)
	require.True(t, s.BearerToken())
}

func (suite *ProviderSuite) Test_ScopedPermissionsConnectionTypes() {
	t := suite.T()
	auth, _, a := setupTestWithOperatorAndAccount(suite)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	require.NoError(t, err)
	types := s.ConnectionTypes()
	require.NoError(t, types.Set("websocket"))
	require.Contains(t, types.Types(), "websocket")
	require.NoError(t, auth.Commit())

	require.NoError(t, auth.Reload())

	o := auth.Operators().Get("O")
	require.NoError(t, err)
	require.NotNil(t, o)

	a = o.Accounts().Get("A")
	require.NoError(t, err)
	require.NotNil(t, a)

	s = a.ScopedSigningKeys().GetScopeByRole("admin")
	require.NotNil(t, s)
	types = s.ConnectionTypes()
	require.Contains(t, types.Types(), "websocket")
}

func (suite *ProviderSuite) Test_ScopedPermissionsConnectionSources() {
	t := suite.T()
	auth, _, a := setupTestWithOperatorAndAccount(suite)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	require.NoError(t, err)
	sources := s.ConnectionSources()
	require.NoError(t, sources.Add("192.0.2.0/24"))
	require.Contains(t, sources.Sources(), "192.0.2.0/24")
	require.NoError(t, auth.Commit())

	require.NoError(t, auth.Reload())

	o := auth.Operators().Get("O")
	require.NoError(t, err)
	require.NotNil(t, o)

	a = o.Accounts().Get("A")
	require.NoError(t, err)
	require.NotNil(t, a)

	s = a.ScopedSigningKeys().GetScopeByRole("admin")
	require.NotNil(t, s)
	sources = s.ConnectionSources()
	require.Contains(t, sources.Sources(), "192.0.2.0/24")
}

func (suite *ProviderSuite) Test_ScopedPermissionsConnectionTimes() {
	t := suite.T()
	auth, _, a := setupTestWithOperatorAndAccount(suite)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	require.NoError(t, err)
	times := s.ConnectionTimes()
	require.NoError(t, times.Set(authb.TimeRange{Start: "08:00:00", End: "12:00:00"}))
	require.Len(t, times.List(), 1)
	require.NoError(t, auth.Commit())

	require.NoError(t, auth.Reload())

	o := auth.Operators().Get("O")
	require.NoError(t, err)
	require.NotNil(t, o)

	a = o.Accounts().Get("A")
	require.NoError(t, err)
	require.NotNil(t, a)

	s = a.ScopedSigningKeys().GetScopeByRole("admin")
	require.NotNil(t, s)
	times = s.ConnectionTimes()
	require.Len(t, times.List(), 1)
	require.Equal(t, times.List()[0].Start, "08:00:00")
	require.Equal(t, times.List()[0].End, "12:00:00")
}

func (suite *ProviderSuite) Test_ScopedPermissionsLocale() {
	t := suite.T()
	auth, _, a := setupTestWithOperatorAndAccount(suite)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	require.NoError(t, err)
	require.NoError(t, s.SetLocale("en_US"))
	require.NoError(t, auth.Commit())

	require.NoError(t, auth.Reload())

	o := auth.Operators().Get("O")
	require.NoError(t, err)
	require.NotNil(t, o)

	a = o.Accounts().Get("A")
	require.NoError(t, err)
	require.NotNil(t, a)

	s = a.ScopedSigningKeys().GetScopeByRole("admin")
	require.NotNil(t, s)
	require.Equal(t, "en_US", s.Locale())
}

func (suite *ProviderSuite) Test_ScopedPermissionsSubject() {
	t := suite.T()
	auth, _, a := setupTestWithOperatorAndAccount(suite)

	admin, err := a.ScopedSigningKeys().AddScope("admin")
	require.NoError(t, err)
	require.NotNil(t, admin)

	pubPerms := admin.PubPermissions()
	require.NoError(t, pubPerms.SetAllow("foo", "bar"))
	require.NoError(t, pubPerms.SetDeny("baz"))

	subPerms := admin.SubPermissions()
	require.NoError(t, subPerms.SetAllow("foo", "bar"))
	require.NoError(t, subPerms.SetDeny("baz"))

	respPerms := admin.ResponsePermissions()
	require.NoError(t, respPerms.SetMaxMessages(10))
	require.NoError(t, respPerms.SetExpires(time.Second))

	require.NoError(t, auth.Reload())

	admin = a.ScopedSigningKeys().GetScopeByRole("admin")
	require.NotNil(t, admin)

	require.Contains(t, admin.PubPermissions().Allow(), "foo")
	require.Contains(t, admin.PubPermissions().Allow(), "bar")
	require.Contains(t, admin.PubPermissions().Deny(), "baz")

	require.Contains(t, admin.SubPermissions().Allow(), "foo")
	require.Contains(t, admin.SubPermissions().Allow(), "bar")
	require.Contains(t, admin.SubPermissions().Deny(), "baz")

	perm := admin.ResponsePermissions()
	require.NotNil(t, perm)
	require.Equal(t, 10, perm.MaxMessages())
	require.Equal(t, time.Second, perm.Expires())
}

func (suite *ProviderSuite) Test_ScopeRotation() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)

	a, err := o.Accounts().Add("A")
	require.NoError(t, err)

	scope, err := a.ScopedSigningKeys().AddScope("admin")
	require.NoError(t, err)
	require.NotNil(t, scope)
	scope2, ok := a.ScopedSigningKeys().GetScope(scope.Key())
	require.True(t, ok)
	require.NotNil(t, scope2)

	key, err := a.ScopedSigningKeys().Rotate(scope.Key())
	require.NoError(t, err)
	require.NotEmpty(t, key)

	scope2, ok = a.ScopedSigningKeys().GetScope(scope.Key())
	require.False(t, ok)
	require.Nil(t, scope2)

	scope2, ok = a.ScopedSigningKeys().GetScope(key)
	require.True(t, ok)
	require.NotNil(t, scope2)

	ok, err = a.ScopedSigningKeys().Delete(key)
	require.NoError(t, err)
	require.True(t, ok)

	scope2, ok = a.ScopedSigningKeys().GetScope(key)
	require.False(t, ok)
	require.Nil(t, scope2)
}

func (suite *ProviderSuite) Test_SigningKeyRotation() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)

	a, err := o.Accounts().Add("A")
	require.NoError(t, err)

	sk, err := a.ScopedSigningKeys().Add()
	require.NoError(t, err)
	require.NotEmpty(t, sk)
	scope, ok := a.ScopedSigningKeys().GetScope(sk)
	require.True(t, ok)
	require.Nil(t, scope)

	u, err := a.Users().Add("U", sk)
	require.NoError(t, err)
	require.NotNil(t, u)

	require.Equal(t, sk, u.Issuer())

	key, err := a.ScopedSigningKeys().Rotate(sk)
	require.NoError(t, err)
	require.NotEmpty(t, key)

	require.Equal(t, key, u.Issuer())
}

func (suite *ProviderSuite) Test_AccountLimits() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)

	require.Equal(t, int64(-1), a.Limits().MaxData())
	require.Equal(t, int64(-1), a.Limits().MaxSubscriptions())
	require.Equal(t, int64(-1), a.Limits().MaxPayload())
	require.Equal(t, int64(-1), a.Limits().MaxConnections())
	require.Equal(t, int64(-1), a.Limits().MaxLeafNodeConnections())
	require.Equal(t, int64(-1), a.Limits().MaxImports())
	require.Equal(t, int64(-1), a.Limits().MaxExports())
	require.True(t, a.Limits().AllowWildcardExports())
	require.False(t, a.Limits().DisallowBearerTokens())

	require.NoError(t, a.Limits().SetMaxData(100))
	require.NoError(t, a.Limits().SetMaxSubscriptions(1_000))
	require.NoError(t, a.Limits().SetMaxPayload(1_0000))
	require.NoError(t, a.Limits().SetMaxConnections(3))
	require.NoError(t, a.Limits().SetMaxLeafNodeConnections(30))
	require.NoError(t, a.Limits().SetMaxImports(300))
	require.NoError(t, a.Limits().SetMaxExports(3_000))
	require.NoError(t, a.Limits().SetAllowWildcardExports(false))
	require.NoError(t, a.Limits().SetDisallowBearerTokens(true))
	require.NoError(t, auth.Commit())
	require.NoError(t, auth.Reload())

	require.Equal(t, int64(100), a.Limits().MaxData())
	require.Equal(t, int64(1_000), a.Limits().MaxSubscriptions())
	require.Equal(t, int64(10_000), a.Limits().MaxPayload())
	require.Equal(t, int64(3), a.Limits().MaxConnections())
	require.Equal(t, int64(30), a.Limits().MaxLeafNodeConnections())
	require.Equal(t, int64(300), a.Limits().MaxImports())
	require.Equal(t, int64(3_000), a.Limits().MaxExports())
	require.False(t, a.Limits().AllowWildcardExports())
	require.True(t, a.Limits().DisallowBearerTokens())
}

func (suite *ProviderSuite) testTier(auth authb.Auth, account authb.Account, tier int8) {
	t := suite.T()
	var err error

	js := account.Limits().JetStream()
	require.False(t, js.IsJetStreamEnabled())
	lim, err := js.Get(tier)
	require.NoError(t, err)
	if tier == 0 {
		require.NotNil(t, lim)
	} else {
		require.Nil(t, lim)
		lim, err = js.Add(tier)
		require.NoError(t, err)
	}
	ok, err := lim.IsUnlimited()
	require.NoError(t, err)
	require.False(t, ok)

	num, err := lim.MaxMemoryStorage()
	require.NoError(t, err)
	require.Equal(t, int64(0), num)

	num, err = lim.MaxDiskStorage()
	require.NoError(t, err)
	require.Equal(t, int64(0), num)

	num, err = lim.MaxMemoryStreamSize()
	require.NoError(t, err)
	require.Equal(t, int64(0), num)

	num, err = lim.MaxDiskStreamSize()
	require.NoError(t, err)
	require.Equal(t, int64(0), num)

	tf, err := lim.MaxStreamSizeRequired()
	require.NoError(t, err)
	require.False(t, tf)

	num, err = lim.MaxStreams()
	require.NoError(t, err)
	require.Equal(t, int64(0), num)

	num, err = lim.MaxConsumers()
	require.NoError(t, err)
	require.Equal(t, int64(0), num)

	num, err = lim.MaxAckPending()
	require.NoError(t, err)
	require.Equal(t, int64(0), num)

	require.NoError(t, lim.SetMaxDiskStorage(1000))
	require.NoError(t, lim.SetMaxMemoryStorage(2000))
	require.NoError(t, lim.SetMaxMemoryStreamSize(4000))
	require.NoError(t, lim.SetMaxDiskStreamSize(8000))
	require.NoError(t, lim.SetMaxStreamSizeRequired(true))
	require.NoError(t, lim.SetMaxStreams(5))
	require.NoError(t, lim.SetMaxConsumers(50))
	require.NoError(t, lim.SetMaxAckPending(22))

	tf, err = lim.IsUnlimited()
	require.NoError(t, err)
	require.False(t, tf)

	require.NoError(t, auth.Commit())
	require.NoError(t, auth.Reload())

	lim, err = js.Get(tier)
	require.NoError(t, err)
	require.NotNil(t, lim)

	tf, err = lim.IsUnlimited()
	require.NoError(t, err)
	require.False(t, tf)

	num, err = lim.MaxDiskStorage()
	require.NoError(t, err)
	require.Equal(t, int64(1000), num)

	num, err = lim.MaxMemoryStorage()
	require.NoError(t, err)
	require.Equal(t, int64(2000), num)

	num, err = lim.MaxMemoryStreamSize()
	require.NoError(t, err)
	require.Equal(t, int64(4000), num)

	num, err = lim.MaxDiskStreamSize()
	require.NoError(t, err)
	require.Equal(t, int64(8000), num)

	tf, err = lim.MaxStreamSizeRequired()
	require.NoError(t, err)
	require.True(t, tf)

	num, err = lim.MaxStreams()
	require.NoError(t, err)
	require.Equal(t, int64(5), num)

	num, err = lim.MaxConsumers()
	require.NoError(t, err)
	require.Equal(t, int64(50), num)

	num, err = lim.MaxAckPending()
	require.NoError(t, err)
	require.Equal(t, int64(22), num)

	require.NoError(t, lim.SetUnlimited())
	tf, err = lim.IsUnlimited()
	require.NoError(t, err)
	require.True(t, tf)

}

func (suite *ProviderSuite) Test_AccountJetStreamLimits() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)
	suite.testTier(auth, a, 0)
	b, err := o.Accounts().Add("B")
	require.NoError(t, err)
	suite.testTier(auth, b, 1)
}
