package tests

import (
	"time"

	"github.com/nats-io/jwt/v2"
	authb "github.com/synadia-io/jwt-auth-builder.go"
)

func (t *ProviderSuite) Test_UserBasics() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	a, err := o.Accounts().Add("A")
	t.NoError(err)
	u, err := a.Users().Add("U", "")
	t.NoError(err)
	t.NotNil(u)
	id := u.Subject()

	// Test that we can get the user back
	t.NoError(auth.Commit())
	t.True(t.Store.UserExists("O", "A", "U"))
	key := t.Store.GetKey(u.Subject())
	t.NotNil(key)

	t.NoError(auth.Reload())
	o, ok := auth.Operators().Get("O")
	t.True(ok)
	a, ok = o.Accounts().Get("A")
	t.True(ok)
	u = a.Users().Get("U")
	t.NotNil(u)
	t.Equal(id, u.Subject())
	key = t.Store.GetKey(u.Subject())
	t.NotNil(key)

	users := a.Users().List()
	t.NoError(err)
	t.Len(users, 1)

	t.NoError(a.Users().Delete("U"))
	t.NoError(auth.Commit())

	users = a.Users().List()
	t.NoError(err)
	t.Empty(users)

	t.False(t.Store.UserExists("O", "A", "U"))
	t.False(t.Store.KeyExists(id))
}

func (t *ProviderSuite) Test_UserWithSigningKey() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	// add an account with a signing key
	a, err := o.Accounts().Add("A")
	t.NoError(err)
	k, err := a.ScopedSigningKeys().Add()
	t.NoError(err)

	// issue the user with the signing key
	u, err := a.Users().Add("U", k)
	t.NoError(err)
	t.NotNil(u)
	ud := u.(*authb.UserData)
	t.Equal(k, ud.Claim.Issuer)
	t.Equal(a.Subject(), ud.Claim.IssuerAccount)
}

func setupScopeUser(t *ProviderSuite) authb.User {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	// add an account with a signing key
	a, err := o.Accounts().Add("A")
	t.NoError(err)
	scope, err := a.ScopedSigningKeys().AddScope("admin")
	t.NoError(err)
	t.NotNil(scope)
	t.NoError(scope.SubPermissions().SetAllow("q"))
	t.NoError(scope.ResponsePermissions().SetMaxMessages(1))

	// issue the user with the signing key
	u, err := a.Users().Add("U", scope.Key())
	t.NoError(err)
	t.NotNil(u)
	t.True(u.IsScoped())
	ud := u.(*authb.UserData)
	t.Equal(scope.Key(), ud.Claim.Issuer)
	t.Equal(a.Subject(), ud.Claim.IssuerAccount)

	return u
}

func (t *ProviderSuite) Test_ScopedUserFailsSetMaxSubscriptions() {
	u := setupScopeUser(t)
	n := u.MaxSubscriptions()
	t.Equal(int64(0), n)
	err := u.SetMaxSubscriptions(100)
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)
}

func (t *ProviderSuite) Test_ScopedUserSetMaxSubscriptions() {
	auth, u := setupUser(t)
	n := u.MaxSubscriptions()
	t.Equal(int64(-1), n)
	err := u.SetMaxSubscriptions(100)
	t.NoError(err)
	t.Equal(int64(100), u.MaxSubscriptions())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	o, ok := auth.Operators().Get("O")
	t.True(ok)
	a, ok := o.Accounts().Get("A")
	t.True(ok)
	u = a.Users().Get("U")
	t.NoError(err)
	t.Equal(int64(100), u.MaxSubscriptions())
}

func (t *ProviderSuite) Test_ScopedUserFailsSetMaxPayload() {
	u := setupScopeUser(t)
	n := u.MaxPayload()
	t.Equal(int64(0), n)
	err := u.SetMaxPayload(100)
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)
}

func (t *ProviderSuite) Test_ScopedUserSetMaxPayload() {
	auth, u := setupUser(t)
	n := u.MaxSubscriptions()
	t.Equal(int64(-1), n)
	err := u.SetMaxPayload(100)
	t.NoError(err)
	t.Equal(int64(100), u.MaxPayload())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	o, ok := auth.Operators().Get("O")
	t.True(ok)
	a, ok := o.Accounts().Get("A")
	t.True(ok)
	u = a.Users().Get("U")
	t.NoError(err)
	t.Equal(int64(100), u.MaxPayload())
}

func (t *ProviderSuite) Test_ScopedUserFailsSetMaxData() {
	u := setupScopeUser(t)
	n := u.MaxData()
	t.Equal(int64(0), n)
	err := u.SetMaxData(100)
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)
}

func (t *ProviderSuite) Test_ScopedUserSetMaxData() {
	auth, u := setupUser(t)
	n := u.MaxSubscriptions()
	t.Equal(int64(-1), n)
	err := u.SetMaxData(100)
	t.NoError(err)
	t.Equal(int64(100), u.MaxData())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	o, ok := auth.Operators().Get("O")
	t.True(ok)
	a, ok := o.Accounts().Get("A")
	t.True(ok)
	u = a.Users().Get("U")
	t.Equal(int64(100), u.MaxData())
}

func (t *ProviderSuite) Test_ScopedUserFailsSetBearerToken() {
	u := setupScopeUser(t)
	n := u.BearerToken()
	t.Equal(false, n)
	err := u.SetBearerToken(true)
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)
}

func (t *ProviderSuite) Test_ScopedUserFailsSetLocale() {
	u := setupScopeUser(t)
	n := u.Locale()
	t.Equal("", n)
	err := u.SetLocale("")
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)
}

func (t *ProviderSuite) Test_ScopedUserFailsPubPermissions() {
	u := setupScopeUser(t)
	n := u.PubPermissions().Allow()
	t.Empty(n)

	err := u.PubPermissions().SetAllow("foo")
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)

	n = u.PubPermissions().Deny()
	t.Empty(n)

	err = u.PubPermissions().SetDeny("foo")
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)
}

func (t *ProviderSuite) Test_ScopedUserFailsSubPermissions() {
	u := setupScopeUser(t)
	n := u.SubPermissions().Allow()
	t.Empty(n)

	err := u.SubPermissions().SetAllow("foo")
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)

	n = u.SubPermissions().Deny()
	t.Empty(n)

	err = u.SubPermissions().SetDeny("foo")
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)
}

func (t *ProviderSuite) Test_ScopedUserFailsRespondPermissions() {
	u := setupScopeUser(t)
	perms := u.ResponsePermissions()
	t.Equal(time.Duration(0), perms.Expires())
	t.Equal(0, perms.MaxMessages())

	err := perms.SetExpires(time.Second)
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)

	err = perms.SetMaxMessages(1)
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)
}

func (t *ProviderSuite) Test_ScopedUserFailsConnectionTypes() {
	u := setupScopeUser(t)
	types := u.ConnectionTypes()
	t.Empty(types.Types())

	err := types.Set("websocket")
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)
}

func (t *ProviderSuite) Test_ScopedUserFailsConnectionSources() {
	u := setupScopeUser(t)
	types := u.ConnectionSources()
	t.Empty(types.Sources())

	err := types.Set("192.0.2.0/24")
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)
}

func (t *ProviderSuite) Test_ScopedUserFailsConnectionTimes() {
	u := setupScopeUser(t)
	times := u.ConnectionTimes()
	t.Empty(times.List())

	err := times.Set(authb.TimeRange{Start: "00:00:00", End: "23:59:01"})
	t.Error(err)
	t.Equal(authb.ErrUserIsScoped, err)
}

func setupUser(t *ProviderSuite) (authb.Auth, authb.User) {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	a, err := o.Accounts().Add("A")
	t.NoError(err)

	u, err := a.Users().Add("U", "")
	t.NoError(err)
	t.NotNil(u)

	return auth, u
}

func (t *ProviderSuite) Test_Creds() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	a, err := o.Accounts().Add("A")
	t.NoError(err)

	u, err := a.Users().Add("U", "")
	t.NoError(err)
	t.NotNil(u)
	creds, err := u.Creds(time.Second)
	t.NoError(err)
	s, err := jwt.ParseDecoratedJWT(creds)
	t.NoError(err)
	uc, err := jwt.DecodeUserClaims(s)
	t.NoError(err)
	t.True(uc.ClaimsData.Expires > 0)

	ud := u.(*authb.UserData)
	t.Equal(int64(0), ud.Claim.Expires)
}

func (t *ProviderSuite) Test_UsersAddedSave() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	t.NotNil(o)
	a, err := o.Accounts().Add("A")
	t.NoError(err)
	t.NotNil(a)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	o, ok := auth.Operators().Get("O")
	t.True(ok)
	a, ok = o.Accounts().Get("A")
	t.True(ok)

	u, err := a.Users().Add("U", "")
	t.NoError(err)
	t.NotNil(u)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	o, ok = auth.Operators().Get("O")
	t.True(ok)
	a, ok = o.Accounts().Get("A")
	t.True(ok)
	u = a.Users().Get("U")
	t.NotNil(u)
}

func (t *ProviderSuite) Test_UsersAddedPermsSave() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	t.NotNil(o)
	a, err := o.Accounts().Add("A")
	t.NoError(err)
	t.NotNil(a)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	o, ok := auth.Operators().Get("O")
	t.True(ok)
	a, ok = o.Accounts().Get("A")
	t.True(ok)

	u, err := a.Users().Add("U", "")
	t.NoError(err)
	t.NotNil(u)
	t.NoError(u.PubPermissions().SetAllow("foo", "bar"))
	t.NoError(u.SubPermissions().SetAllow("_inbox.me"))

	t.Contains(u.SubPermissions().Allow(), "_inbox.me")
	t.Contains(u.PubPermissions().Allow(), "foo")
	t.Contains(u.PubPermissions().Allow(), "bar")

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	o, ok = auth.Operators().Get("O")
	t.True(ok)
	a, ok = o.Accounts().Get("A")
	t.True(ok)
	u = a.Users().Get("U")
	t.NotNil(u)

	t.Contains(u.SubPermissions().Allow(), "_inbox.me")
	t.Contains(u.PubPermissions().Allow(), "foo")
	t.Contains(u.PubPermissions().Allow(), "bar")

	creds, err := u.Creds(time.Hour * 24 * 365)
	t.NoError(err)

	token, err := jwt.ParseDecoratedJWT(creds)
	t.NoError(err)

	uc, err := jwt.DecodeUserClaims(token)
	t.NoError(err)
	t.Contains(uc.Permissions.Pub.Allow, "foo")
	t.Contains(uc.Permissions.Pub.Allow, "bar")
	t.Contains(uc.Permissions.Sub.Allow, "_inbox.me")
}
