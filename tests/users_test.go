package tests

import (
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
	authb "github.com/synadia-io/jwt-auth-builder.go"
	"time"
)

func (suite *ProviderSuite) Test_UserBasics() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
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
	require.True(t, suite.Store.UserExists("O", "A", "U"))
	key := suite.Store.GetKey(u.Subject())
	require.NotNil(t, key)

	require.NoError(t, auth.Reload())
	o = auth.Operators().Get("O")
	require.NoError(t, err)
	a = o.Accounts().Get("A")
	require.NoError(t, err)
	u = a.Users().Get("U")
	require.NotNil(t, u)
	require.Equal(t, id, u.Subject())
	key = suite.Store.GetKey(u.Subject())
	require.NotNil(t, key)

	users := a.Users().List()
	require.NoError(t, err)
	require.Len(t, users, 1)

	require.NoError(t, a.Users().Delete("U"))
	require.NoError(t, auth.Commit())

	users = a.Users().List()
	require.NoError(t, err)
	require.Empty(t, users)

	require.False(t, suite.Store.UserExists("O", "A", "U"))
	require.False(t, suite.Store.KeyExists(id))
}

func (suite *ProviderSuite) Test_UserWithSigningKey() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
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
	ud := u.(*authb.UserData)
	require.Equal(t, k, ud.Claim.Issuer)
	require.Equal(t, a.Subject(), ud.Claim.IssuerAccount)
}

func setupScopeUser(suite *ProviderSuite) authb.User {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
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
	ud := u.(*authb.UserData)
	require.Equal(t, scope.Key(), ud.Claim.Issuer)
	require.Equal(t, a.Subject(), ud.Claim.IssuerAccount)

	return u
}

func (suite *ProviderSuite) Test_ScopedUserFailsSetMaxSubscriptions() {
	t := suite.T()
	u := setupScopeUser(suite)
	n := u.MaxSubscriptions()
	require.Equal(t, int64(0), n)
	err := u.SetMaxSubscriptions(100)
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)
}

func (suite *ProviderSuite) Test_ScopedUserSetMaxSubscriptions() {
	t := suite.T()
	auth, u := setupUser(suite)
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

func (suite *ProviderSuite) Test_ScopedUserFailsSetMaxPayload() {
	t := suite.T()
	u := setupScopeUser(suite)
	n := u.MaxPayload()
	require.Equal(t, int64(0), n)
	err := u.SetMaxPayload(100)
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)
}

func (suite *ProviderSuite) Test_ScopedUserSetMaxPayload() {
	t := suite.T()
	auth, u := setupUser(suite)
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

func (suite *ProviderSuite) Test_ScopedUserFailsSetMaxData() {
	t := suite.T()
	u := setupScopeUser(suite)
	n := u.MaxData()
	require.Equal(t, int64(0), n)
	err := u.SetMaxData(100)
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)
}

func (suite *ProviderSuite) Test_ScopedUserSetMaxData() {
	t := suite.T()
	auth, u := setupUser(suite)
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

func (suite *ProviderSuite) Test_ScopedUserFailsSetBearerToken() {
	t := suite.T()
	u := setupScopeUser(suite)
	n := u.BearerToken()
	require.Equal(t, false, n)
	err := u.SetBearerToken(true)
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)
}

func (suite *ProviderSuite) Test_ScopedUserFailsSetLocale() {
	t := suite.T()
	u := setupScopeUser(suite)
	n := u.Locale()
	require.Equal(t, "", n)
	err := u.SetLocale("")
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)
}

func (suite *ProviderSuite) Test_ScopedUserFailsPubPermissions() {
	t := suite.T()
	u := setupScopeUser(suite)
	n := u.PubPermissions().Allow()
	require.Empty(t, n)

	err := u.PubPermissions().SetAllow("foo")
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)

	n = u.PubPermissions().Deny()
	require.Empty(t, n)

	err = u.PubPermissions().SetDeny("foo")
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)
}

func (suite *ProviderSuite) Test_ScopedUserFailsSubPermissions() {
	t := suite.T()
	u := setupScopeUser(suite)
	n := u.SubPermissions().Allow()
	require.Empty(t, n)

	err := u.SubPermissions().SetAllow("foo")
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)

	n = u.SubPermissions().Deny()
	require.Empty(t, n)

	err = u.SubPermissions().SetDeny("foo")
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)
}

func (suite *ProviderSuite) Test_ScopedUserFailsRespondPermissions() {
	t := suite.T()
	u := setupScopeUser(suite)
	perms := u.ResponsePermissions()
	require.Equal(t, time.Duration(0), perms.Expires())
	require.Equal(t, 0, perms.MaxMessages())

	err := perms.SetExpires(time.Second)
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)

	err = perms.SetMaxMessages(1)
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)
}

func (suite *ProviderSuite) Test_ScopedUserFailsConnectionTypes() {
	t := suite.T()
	u := setupScopeUser(suite)
	types := u.ConnectionTypes()
	require.Empty(t, types.Types())

	err := types.Set("websocket")
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)
}

func (suite *ProviderSuite) Test_ScopedUserFailsConnectionSources() {
	t := suite.T()
	u := setupScopeUser(suite)
	types := u.ConnectionSources()
	require.Empty(t, types.Sources())

	err := types.Set("192.0.2.0/24")
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)
}

func (suite *ProviderSuite) Test_ScopedUserFailsConnectionTimes() {
	t := suite.T()
	u := setupScopeUser(suite)
	times := u.ConnectionTimes()
	require.Empty(t, times.List())

	err := times.Set(authb.TimeRange{Start: "00:00:00", End: "23:59:01"})
	require.Error(t, err)
	require.Equal(t, authb.ErrUserIsScoped, err)
}

func setupUser(suite *ProviderSuite) (authb.Auth, authb.User) {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)

	u, err := a.Users().Add("U", "")
	require.NoError(t, err)
	require.NotNil(t, u)

	return auth, u
}

func (suite *ProviderSuite) Test_Creds() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
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

	ud := u.(*authb.UserData)
	require.Equal(t, int64(0), ud.Claim.Expires)
}

func (suite *ProviderSuite) Test_UsersAddedSave() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	require.NotNil(t, o)
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)
	require.NotNil(t, a)

	require.NoError(t, auth.Commit())
	require.NoError(t, auth.Reload())

	o = auth.Operators().Get("O")
	require.NotNil(t, o)
	a = o.Accounts().Get("A")
	require.NotNil(t, a)

	u, err := a.Users().Add("U", "")
	require.NoError(t, err)
	require.NotNil(t, u)

	require.NoError(t, auth.Commit())
	require.NoError(t, auth.Reload())

	o = auth.Operators().Get("O")
	require.NotNil(t, o)
	a = o.Accounts().Get("A")
	require.NotNil(t, a)
	u = a.Users().Get("U")
	require.NotNil(t, u)
}

func (suite *ProviderSuite) Test_UsersAddedPermsSave() {
	auth, err := authb.NewAuth(suite.Provider)
	suite.NoError(err)
	o, err := auth.Operators().Add("O")
	suite.NoError(err)
	suite.NotNil(o)
	a, err := o.Accounts().Add("A")
	suite.NoError(err)
	suite.NotNil(a)

	suite.NoError(auth.Commit())
	suite.NoError(auth.Reload())

	o = auth.Operators().Get("O")
	suite.NotNil(o)
	a = o.Accounts().Get("A")
	suite.NotNil(a)

	u, err := a.Users().Add("U", "")
	suite.NoError(err)
	suite.NotNil(u)
	suite.NoError(u.PubPermissions().SetAllow("foo", "bar"))
	suite.NoError(u.SubPermissions().SetAllow("_inbox.me"))

	suite.Contains(u.SubPermissions().Allow(), "_inbox.me")
	suite.Contains(u.PubPermissions().Allow(), "foo")
	suite.Contains(u.PubPermissions().Allow(), "bar")

	suite.NoError(auth.Commit())
	suite.NoError(auth.Reload())

	o = auth.Operators().Get("O")
	suite.NotNil(o)
	a = o.Accounts().Get("A")
	suite.NotNil(a)
	u = a.Users().Get("U")
	suite.NotNil(u)

	suite.Contains(u.SubPermissions().Allow(), "_inbox.me")
	suite.Contains(u.PubPermissions().Allow(), "foo")
	suite.Contains(u.PubPermissions().Allow(), "bar")

	creds, err := u.Creds(time.Hour * 24 * 365)
	suite.NoError(err)

	token, err := jwt.ParseDecoratedJWT(creds)
	suite.NoError(err)

	uc, err := jwt.DecodeUserClaims(token)
	suite.NoError(err)
	suite.Contains(uc.Permissions.Pub.Allow, "foo")
	suite.Contains(uc.Permissions.Pub.Allow, "bar")
	suite.Contains(uc.Permissions.Sub.Allow, "_inbox.me")

}
