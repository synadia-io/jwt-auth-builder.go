package nats_auth

import (
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func Test_UserBasics(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)
	u, err := a.Users().Add("U", "")
	require.NoError(t, err)
	require.NotNil(t, u)
	id := u.Subject()

	// Test that we can get the user back
	require.NoError(t, auth.Commit())
	require.True(t, ts.UserExists("O", "A", "U"))
	key := ts.GetKey(t, u.Subject())
	require.NotNil(t, key)

	require.NoError(t, auth.Reload())
	o = auth.Operators().Get("O")
	require.NoError(t, err)
	a = o.Accounts().Get("A")
	require.NoError(t, err)
	u = a.Users().Get("U")
	require.NotNil(t, u)
	require.Equal(t, id, u.Subject())
	key = ts.GetKey(t, u.Subject())
	require.NotNil(t, key)

	users := a.Users().List()
	require.NoError(t, err)
	require.Len(t, users, 1)

	require.NoError(t, a.Users().Delete("U"))
	require.NoError(t, auth.Commit())

	users = a.Users().List()
	require.NoError(t, err)
	require.Empty(t, users)

	require.False(t, ts.UserExists("O", "A", "U"))
	require.False(t, ts.KeyExists(t, id))
}

func Test_UserWithSigningKey(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	// add an account with a signing key
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)
	k, err := a.ScopedSigningKeys().Add()
	require.NoError(t, err)

	// issue the user with the signing key
	u, err := a.Users().Add("U", k)
	require.NoError(t, err)
	require.NotNil(t, u)
	ud := u.(*UserData)
	require.Equal(t, k, ud.Claim.Issuer)
	require.Equal(t, a.Subject(), ud.Claim.IssuerAccount)
}

func setupScopeUser(t *testing.T) (*TestStore, User) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	// add an account with a signing key
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)
	scope, err := a.ScopedSigningKeys().AddScope("admin")
	require.NoError(t, err)
	require.NotNil(t, scope)
	require.NoError(t, scope.SubPermissions().SetAllow("q"))
	require.NoError(t, scope.ResponsePermissions().SetMaxMessages(1))

	// issue the user with the signing key
	u, err := a.Users().Add("U", scope.Key())
	require.NoError(t, err)
	require.NotNil(t, u)
	require.True(t, u.IsScoped())
	ud := u.(*UserData)
	require.Equal(t, scope.Key(), ud.Claim.Issuer)
	require.Equal(t, a.Subject(), ud.Claim.IssuerAccount)

	return ts, u
}

func Test_ScopedUserFailsSetMaxSubscriptions(t *testing.T) {
	_, u := setupScopeUser(t)
	n := u.MaxSubscriptions()
	require.Equal(t, int64(0), n)
	err := u.SetMaxSubscriptions(100)
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)
}

func Test_ScopedUserSetMaxSubscriptions(t *testing.T) {
	_, auth, u := setupUser(t)
	n := u.MaxSubscriptions()
	require.Equal(t, int64(-1), n)
	err := u.SetMaxSubscriptions(100)
	require.NoError(t, err)
	require.Equal(t, int64(100), u.MaxSubscriptions())

	require.NoError(t, auth.Commit())
	require.NoError(t, auth.Reload())

	o := auth.Operators().Get("O")
	require.NoError(t, err)
	a := o.Accounts().Get("A")
	require.NoError(t, err)
	u = a.Users().Get("U")
	require.NoError(t, err)
	require.Equal(t, int64(100), u.MaxSubscriptions())
}

func Test_ScopedUserFailsSetMaxPayload(t *testing.T) {
	_, u := setupScopeUser(t)
	n := u.MaxPayload()
	require.Equal(t, int64(0), n)
	err := u.SetMaxPayload(100)
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)
}

func Test_ScopedUserSetMaxPayload(t *testing.T) {
	_, auth, u := setupUser(t)
	n := u.MaxSubscriptions()
	require.Equal(t, int64(-1), n)
	err := u.SetMaxPayload(100)
	require.NoError(t, err)
	require.Equal(t, int64(100), u.MaxPayload())

	require.NoError(t, auth.Commit())
	require.NoError(t, auth.Reload())

	o := auth.Operators().Get("O")
	require.NoError(t, err)
	a := o.Accounts().Get("A")
	require.NoError(t, err)
	u = a.Users().Get("U")
	require.NoError(t, err)
	require.Equal(t, int64(100), u.MaxPayload())
}

func Test_ScopedUserFailsSetMaxData(t *testing.T) {
	_, u := setupScopeUser(t)
	n := u.MaxData()
	require.Equal(t, int64(0), n)
	err := u.SetMaxData(100)
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)
}

func Test_ScopedUserSetMaxData(t *testing.T) {
	_, auth, u := setupUser(t)
	n := u.MaxSubscriptions()
	require.Equal(t, int64(-1), n)
	err := u.SetMaxData(100)
	require.NoError(t, err)
	require.Equal(t, int64(100), u.MaxData())

	require.NoError(t, auth.Commit())
	require.NoError(t, auth.Reload())

	o := auth.Operators().Get("O")
	require.NoError(t, err)
	a := o.Accounts().Get("A")
	require.NoError(t, err)
	u = a.Users().Get("U")
	require.NoError(t, err)
	require.Equal(t, int64(100), u.MaxData())
}

func Test_ScopedUserFailsSetBearerToken(t *testing.T) {
	_, u := setupScopeUser(t)
	n := u.BearerToken()
	require.Equal(t, false, n)
	err := u.SetBearerToken(true)
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)
}

func Test_ScopedUserFailsSetLocale(t *testing.T) {
	_, u := setupScopeUser(t)
	n := u.Locale()
	require.Equal(t, "", n)
	err := u.SetLocale("")
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)
}

func Test_ScopedUserFailsPubPermissions(t *testing.T) {
	_, u := setupScopeUser(t)
	n := u.PubPermissions().Allow()
	require.Empty(t, n)

	err := u.PubPermissions().SetAllow("foo")
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)

	n = u.PubPermissions().Deny()
	require.Empty(t, n)

	err = u.PubPermissions().SetDeny("foo")
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)
}

func Test_ScopedUserFailsSubPermissions(t *testing.T) {
	_, u := setupScopeUser(t)
	n := u.SubPermissions().Allow()
	require.Empty(t, n)

	err := u.SubPermissions().SetAllow("foo")
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)

	n = u.SubPermissions().Deny()
	require.Empty(t, n)

	err = u.SubPermissions().SetDeny("foo")
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)
}

func Test_ScopedUserFailsRespondPermissions(t *testing.T) {
	_, u := setupScopeUser(t)
	perms := u.ResponsePermissions()
	require.Equal(t, time.Duration(0), perms.Expires())
	require.Equal(t, 0, perms.MaxMessages())

	err := perms.SetExpires(time.Second)
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)

	err = perms.SetMaxMessages(1)
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)
}

func Test_ScopedUserFailsConnectionTypes(t *testing.T) {
	_, u := setupScopeUser(t)
	types := u.ConnectionTypes()
	require.Empty(t, types.Types())

	err := types.Set("websocket")
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)
}

func Test_ScopedUserFailsConnectionSources(t *testing.T) {
	_, u := setupScopeUser(t)
	types := u.ConnectionSources()
	require.Empty(t, types.Sources())

	err := types.Set("192.0.2.0/24")
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)
}

func Test_ScopedUserFailsConnectionTimes(t *testing.T) {
	_, u := setupScopeUser(t)
	times := u.ConnectionTimes()
	require.Empty(t, times.List())

	err := times.Set(TimeRange{Start: "00:00:00", End: "23:59:01"})
	require.Error(t, err)
	require.Equal(t, ErrUserIsScoped, err)
}

func setupUser(t *testing.T) (*TestStore, Auth, User) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)

	u, err := a.Users().Add("U", "")
	require.NoError(t, err)
	require.NotNil(t, u)

	return ts, auth, u
}

func Test_Creds(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)

	u, err := a.Users().Add("U", "")
	require.NoError(t, err)
	require.NotNil(t, u)
	creds, err := u.Creds(time.Second)
	require.NoError(t, err)
	s, err := jwt.ParseDecoratedJWT(creds)
	require.NoError(t, err)
	uc, err := jwt.DecodeUserClaims(s)
	require.NoError(t, err)
	require.True(t, uc.ClaimsData.Expires > 0)

	ud := u.(*UserData)
	require.Equal(t, int64(0), ud.Claim.Expires)
}
