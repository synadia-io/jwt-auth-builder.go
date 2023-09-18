package nats_auth

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func Test_AccountsCrud(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
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
	require.True(t, ts.AccountExists("O", "B"))
	require.False(t, ts.AccountExists("O", "A"))
}

func Test_AccountsBasics(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)

	a, err := o.Accounts().Add("A")
	require.NoError(t, err)

	ai := a.(*AccountData)
	require.Equal(t, ai.Claim.Subject, a.Subject())
	require.Equal(t, o.Subject(), a.Issuer())
}

func setupTestWithOperatorAndAccount(t *testing.T) (Auth, Operator, Account) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	require.NoError(t, auth.Commit())

	a, err := o.Accounts().Add("A")
	require.NoError(t, err)
	return auth, o, a
}

func Test_ScopedPermissionsMaxSubs(t *testing.T) {
	auth, _, a := setupTestWithOperatorAndAccount(t)
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

func Test_ScopedPermissionsMaxPayload(t *testing.T) {
	auth, _, a := setupTestWithOperatorAndAccount(t)
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

func Test_ScopedPermissionsMaxData(t *testing.T) {
	auth, _, a := setupTestWithOperatorAndAccount(t)
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

func Test_ScopedPermissionsBearerToken(t *testing.T) {
	auth, _, a := setupTestWithOperatorAndAccount(t)
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

func Test_ScopedPermissionsConnectionTypes(t *testing.T) {
	auth, _, a := setupTestWithOperatorAndAccount(t)
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

func Test_ScopedPermissionsConnectionSources(t *testing.T) {
	auth, _, a := setupTestWithOperatorAndAccount(t)
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

func Test_ScopedPermissionsConnectionTimes(t *testing.T) {
	auth, _, a := setupTestWithOperatorAndAccount(t)
	s, err := a.ScopedSigningKeys().AddScope("admin")
	require.NoError(t, err)
	times := s.ConnectionTimes()
	require.NoError(t, times.Set(TimeRange{Start: "08:00:00", End: "12:00:00"}))
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

func Test_ScopedPermissionsLocale(t *testing.T) {
	auth, _, a := setupTestWithOperatorAndAccount(t)
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

func Test_ScopedPermissionsSubject(t *testing.T) {
	auth, _, a := setupTestWithOperatorAndAccount(t)

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

func Test_ScopeRotation(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
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

func Test_SigningKeyRotation(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
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
