package tests

import (
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
	authb "github.com/synadia-io/jwt-auth-builder.go"
)

func (suite *ProviderSuite) Test_OperatorBasics() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)

	operators := auth.Operators()
	require.Empty(t, operators.List())

	o := auth.Operators().Get("O")
	require.NoError(t, err)
	require.Nil(t, o)
	o, err = operators.Add("O")
	require.NoError(t, err)
	require.NotNil(t, o)

	require.NoError(t, err)
	require.Len(t, operators.List(), 1)
	require.Equal(t, "O", operators.List()[0].Name())
	require.False(t, suite.Store.OperatorExists("O"))

	require.NoError(t, auth.Commit())

	oc := suite.Store.GetOperator("O")
	require.NotNil(t, oc)
	require.Equal(t, "O", oc.Name)
	require.True(t, suite.Store.OperatorExists("O"))

	key := suite.Store.GetKey(oc.Subject)
	require.NotNil(t, key)
	require.Equal(t, oc.Subject, key.Public)
}

func (suite *ProviderSuite) Test_SkUpdate() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)

	operators := auth.Operators()
	require.Empty(t, operators.List())

	o := auth.Operators().Get("O")
	require.NoError(t, err)
	require.Nil(t, o)
	o, err = operators.Add("O")
	require.NoError(t, err)
	require.NotNil(t, o)

	require.NoError(t, auth.Commit())
	require.NoError(t, auth.Reload())

	o = operators.Get("O")
	require.NotNil(t, o)

	k, err := o.SigningKeys().Add()
	require.NoError(t, err)
	require.NotEmpty(t, k)

	require.NoError(t, auth.Commit())
	require.NoError(t, auth.Reload())

	o = operators.Get("O")
	require.NotNil(t, o)
	keys := o.SigningKeys().List()
	require.Len(t, keys, 1)
	require.Contains(t, keys, k)
}

func (suite *ProviderSuite) Test_OperatorValidation() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	require.Error(t, o.SetOperatorServiceURL("foo://localhost:8080"))
}

func (suite *ProviderSuite) Test_OperatorLoads() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	require.NotNil(t, o)
	require.NoError(t, auth.Commit())

	auth, err = authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o = auth.Operators().Get("O")
	require.NoError(t, err)
	require.NotNil(t, o)
}

func (suite *ProviderSuite) Test_OperatorSigningKeys() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	sk1, err := o.SigningKeys().Add()
	require.NoError(t, err)
	require.NotEmpty(t, sk1)
	sk2, err := o.SigningKeys().Add()
	require.NoError(t, err)
	require.NotEmpty(t, sk2)
	sk3, err := o.SigningKeys().Add()
	require.NoError(t, err)
	require.NotEmpty(t, sk3)

	keys := o.SigningKeys().List()
	require.Len(t, keys, 3)
	require.Contains(t, keys, sk1)
	require.Contains(t, keys, sk2)
	require.Contains(t, keys, sk3)
	require.NoError(t, auth.Commit())

	k := suite.Store.GetKey(sk1)
	require.NotNil(t, k)
	k = suite.Store.GetKey(sk2)
	require.NotNil(t, k)
	k = suite.Store.GetKey(sk3)
	require.NotNil(t, k)

	sk1a, err := o.SigningKeys().Rotate(sk1)
	require.NoError(t, err)

	ok, err := o.SigningKeys().Delete(sk2)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, auth.Commit())

	ok, err = o.SigningKeys().Delete(sk2)
	require.NoError(t, err)
	require.False(t, ok)

	keys = o.SigningKeys().List()
	require.Len(t, keys, 2)
	require.Contains(t, keys, sk1a)
	require.Contains(t, keys, sk3)
}

func (suite *ProviderSuite) Test_OperatorAccountServerURL() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	require.NoError(t, o.SetAccountServerURL("http://localhost:8080"))
	require.NoError(t, auth.Commit())
	require.Equal(t, "http://localhost:8080", o.AccountServerURL())

	oc := suite.Store.GetOperator("O")
	require.Equal(t, "http://localhost:8080", oc.AccountServerURL)
}

func (suite *ProviderSuite) Test_OperatorServiceURL() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	require.NoError(t, o.SetOperatorServiceURL("nats://localhost:4222"))
	require.NoError(t, auth.Commit())
	require.Equal(t, "nats://localhost:4222", o.OperatorServiceURLs()[0])

	oc := suite.Store.GetOperator("O")
	require.Equal(t, "nats://localhost:4222", oc.OperatorServiceURLs[0])
}

func (suite *ProviderSuite) Test_OperatorUsesMainKeyToSignAccount() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)
	// no signing keys on the operator, so the main key was used
	require.NotNil(t, o.Subject(), a.Issuer())
	require.NoError(t, auth.Commit())
}

func (suite *ProviderSuite) Test_OperatorUsesSigningKeyToSignAccount() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	sk, err := o.SigningKeys().Add()
	require.NoError(t, err)
	require.NotEmpty(t, sk)
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)
	require.NotNil(t, sk, a.Issuer())
	require.NoError(t, auth.Commit())

	ac := suite.Store.GetAccount("O", "A")
	require.Equal(t, sk, ac.ClaimsData.Issuer)
}

func (suite *ProviderSuite) Test_OperatorRotate() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	sk, err := o.SigningKeys().Add()
	require.NoError(t, err)
	require.NotEmpty(t, sk)
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)
	require.Equal(t, sk, a.Issuer())
	require.NoError(t, auth.Commit())

	sk2, err := o.SigningKeys().Rotate(sk)
	require.NoError(t, err)
	require.Equal(t, sk2, a.Issuer())
	require.NoError(t, auth.Commit())

	require.False(t, suite.Store.KeyExists(sk))
	require.True(t, suite.Store.KeyExists(sk2))
}

func (suite *ProviderSuite) Test_OperatorSystemAccount() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	require.Nil(t, o.SystemAccount())
	a, err := o.Accounts().Add("SYS")
	require.NoError(t, err)
	require.NoError(t, o.SetSystemAccount(a))
	require.NotNil(t, o.SystemAccount())

	require.Error(t, o.Accounts().Delete("SYS"))
	require.NoError(t, o.SetSystemAccount(nil))
	require.Nil(t, o.SystemAccount())
	require.NoError(t, o.Accounts().Delete("SYS"))
}

func (suite *ProviderSuite) Test_OperatorImport() {
	t := suite.T()
	auth, err := authb.NewAuth(suite.Provider)
	require.NoError(t, err)

	kp, err := authb.KeyFor(nkeys.PrefixByteOperator)
	require.NoError(t, err)

	oc := jwt.NewOperatorClaims(kp.Public)
	oc.Name = "O"
	skp, err := authb.KeyFor(nkeys.PrefixByteOperator)
	require.NoError(t, err)
	oc.SigningKeys.Add(skp.Public)

	token, err := oc.Encode(kp.Pair)
	require.NoError(t, err)

	o, err := auth.Operators().Import(
		[]byte(token),
		[]string{string(kp.Seed), string(skp.Seed)})
	require.NoError(t, err)
	require.NotNil(t, o)

	require.NoError(t, auth.Commit())
	require.NoError(t, auth.Reload())
	o = auth.Operators().Get("O")
	require.NotNil(t, o)
	require.Equal(t, kp.Public, o.Subject())
	require.Equal(t, skp.Public, o.SigningKeys().List()[0])
}
