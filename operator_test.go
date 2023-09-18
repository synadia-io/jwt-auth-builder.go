package nats_auth

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_OperatorBasics(t *testing.T) {
	ts := NewTestStore(t)

	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)

	operators := auth.Operators()
	require.NoError(t, err)
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
	require.False(t, ts.OperatorExists("O"))

	require.NoError(t, auth.Commit())

	oc := ts.GetOperator(t, "O")
	require.NotNil(t, oc)
	require.Equal(t, "O", oc.Name)
	require.True(t, ts.OperatorExists("O"))

	key := ts.GetKey(t, oc.Subject)
	require.NotNil(t, key)
	require.Equal(t, oc.Subject, key.Public)
}

func Test_OperatorValidation(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	require.Error(t, o.SetOperatorServiceURL("foo://localhost:8080"))
}

func Test_OperatorLoads(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	require.NotNil(t, o)
	require.NoError(t, auth.Commit())

	auth, err = NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)
	o = auth.Operators().Get("O")
	require.NoError(t, err)
	require.NotNil(t, o)
}

func Test_OperatorSigningKeys(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
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

	k := ts.GetKey(t, sk1)
	require.NotNil(t, k)
	k = ts.GetKey(t, sk2)
	require.NotNil(t, k)
	k = ts.GetKey(t, sk3)
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

func Test_OperatorAccountServerURL(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	require.NoError(t, o.SetAccountServerURL("http://localhost:8080"))
	require.NoError(t, auth.Commit())
	require.Equal(t, "http://localhost:8080", o.AccountServerURL())

	oc := ts.GetOperator(t, "O")
	require.Equal(t, "http://localhost:8080", oc.AccountServerURL)
}

func Test_OperatorServiceURL(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	require.NoError(t, o.SetOperatorServiceURL("nats://localhost:4222"))
	require.NoError(t, auth.Commit())
	require.Equal(t, "nats://localhost:4222", o.OperatorServiceURLs()[0])

	oc := ts.GetOperator(t, "O")
	require.Equal(t, "nats://localhost:4222", oc.OperatorServiceURLs[0])
}

func Test_OperatorUsesMainKeyToSignAccount(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
	require.NoError(t, err)
	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)
	// no signing keys on the operator, so the main key was used
	require.NotNil(t, o.Subject(), a.Issuer())
	require.NoError(t, auth.Commit())
}

func Test_OperatorUsesSigningKeyToSignAccount(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
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

	ac := ts.GetAccount(t, "O", "A")
	require.Equal(t, sk, ac.ClaimsData.Issuer)
}

func Test_OperatorRotate(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
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

	require.False(t, ts.KeyExists(t, sk))
	require.True(t, ts.KeyExists(t, sk2))
}

func Test_OperatorSystemAccount(t *testing.T) {
	ts := NewTestStore(t)
	auth, err := NewAuth(NewNscAuth(ts.StoresDir(), ts.KeysDir()))
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
