package tests

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	authb "github.com/synadia-io/jwt-auth-builder.go"
	"github.com/synadia-io/jwt-auth-builder.go/providers/nsc"
)

func (t *ProviderSuite) Test_OperatorBasics() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	operators := auth.Operators()
	t.Empty(operators.List())

	_, err = auth.Operators().Get("O")
	t.ErrorIs(err, authb.ErrNotFound)

	o, err := operators.Add("O")
	t.NoError(err)
	t.NotNil(o)

	t.NoError(err)
	t.Len(operators.List(), 1)
	t.Equal("O", operators.List()[0].Name())
	t.False(t.Store.OperatorExists("O"))

	t.NoError(auth.Commit())

	oc := t.Store.GetOperator("O")
	t.NotNil(oc)
	t.Equal("O", oc.Name)
	t.True(t.Store.OperatorExists("O"))

	key := t.Store.GetKey(oc.Subject)
	t.NotNil(key)
	t.Equal(oc.Subject, key.Public)
}

func (t *ProviderSuite) Test_SkUpdate() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	operators := auth.Operators()
	t.Empty(operators.List())

	_, err = auth.Operators().Get("O")
	t.True(errors.Is(err, authb.ErrNotFound))
	o, err := operators.Add("O")
	t.NoError(err)
	t.NotNil(o)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	o, err = operators.Get("O")
	t.NoError(err)

	k, err := o.SigningKeys().Add()
	t.NoError(err)
	t.NotEmpty(k)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	o, err = operators.Get("O")
	t.NoError(err)
	keys := o.SigningKeys().List()
	t.Len(keys, 1)
	t.Contains(keys, k)
}

func (t *ProviderSuite) Test_OperatorValidation() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	t.Error(o.SetOperatorServiceURL("foo://localhost:8080"))
}

func (t *ProviderSuite) Test_OperatorLoads() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	t.NotNil(o)
	t.NoError(auth.Commit())

	auth, err = authb.NewAuth(t.Provider)
	t.NoError(err)
	_, err = auth.Operators().Get("O")
	t.NoError(err)
}

func (t *ProviderSuite) Test_OperatorSigningKeys() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	sk1, err := o.SigningKeys().Add()
	t.NoError(err)
	t.NotEmpty(sk1)
	sk2, err := o.SigningKeys().Add()
	t.NoError(err)
	t.NotEmpty(sk2)
	sk3, err := o.SigningKeys().Add()
	t.NoError(err)
	t.NotEmpty(sk3)

	keys := o.SigningKeys().List()
	t.Len(keys, 3)
	t.Contains(keys, sk1)
	t.Contains(keys, sk2)
	t.Contains(keys, sk3)
	t.NoError(auth.Commit())

	k := t.Store.GetKey(sk1)
	t.NotNil(k)
	k = t.Store.GetKey(sk2)
	t.NotNil(k)
	k = t.Store.GetKey(sk3)
	t.NotNil(k)

	sk1a, err := o.SigningKeys().Rotate(sk1)
	t.NoError(err)

	ok, err := o.SigningKeys().Delete(sk2)
	t.NoError(err)
	t.True(ok)
	t.NoError(auth.Commit())

	ok, err = o.SigningKeys().Delete(sk2)
	t.NoError(err)
	t.False(ok)

	keys = o.SigningKeys().List()
	t.Len(keys, 2)
	t.Contains(keys, sk1a)
	t.Contains(keys, sk3)
}

func (t *ProviderSuite) Test_OperatorAccountServerURL() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	t.NoError(o.SetAccountServerURL("http://localhost:8080"))
	t.NoError(auth.Commit())
	t.Equal("http://localhost:8080", o.AccountServerURL())

	oc := t.Store.GetOperator("O")
	t.Equal("http://localhost:8080", oc.AccountServerURL)
}

func (t *ProviderSuite) Test_OperatorServiceURL() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	t.NoError(o.SetOperatorServiceURL("nats://localhost:4222"))
	t.NoError(auth.Commit())
	t.Equal("nats://localhost:4222", o.OperatorServiceURLs()[0])

	oc := t.Store.GetOperator("O")
	t.Equal("nats://localhost:4222", oc.OperatorServiceURLs[0])
}

func (t *ProviderSuite) Test_OperatorUsesMainKeyToSignAccount() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	a, err := o.Accounts().Add("A")
	t.NoError(err)
	// no signing keys on the operator, so the main key was used
	t.NotNil(o.Subject(), a.Issuer())
	t.NoError(auth.Commit())
}

func (t *ProviderSuite) Test_OperatorUsesSigningKeyToSignAccount() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	sk, err := o.SigningKeys().Add()
	t.NoError(err)
	t.NotEmpty(sk)
	a, err := o.Accounts().Add("A")
	t.NoError(err)
	t.NotNil(sk, a.Issuer())
	t.NoError(auth.Commit())

	ac := t.Store.GetAccount("O", "A")
	t.Equal(sk, ac.ClaimsData.Issuer)
}

func (t *ProviderSuite) Test_OperatorRotate() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	sk, err := o.SigningKeys().Add()
	t.NoError(err)
	t.NotEmpty(sk)
	a, err := o.Accounts().Add("A")
	t.NoError(err)
	t.Equal(sk, a.Issuer())
	t.NoError(auth.Commit())

	sk2, err := o.SigningKeys().Rotate(sk)
	t.NoError(err)
	t.Equal(sk2, a.Issuer())
	t.NoError(auth.Commit())

	t.False(t.Store.KeyExists(sk))
	t.True(t.Store.KeyExists(sk2))
}

func (t *ProviderSuite) Test_OperatorSystemAccount() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	a, err := o.SystemAccount()
	t.Nil(err)
	t.Nil(a)
	a, err = o.Accounts().Add("SYS")
	t.NoError(err)
	t.NoError(o.SetSystemAccount(a))
	a, err = o.SystemAccount()
	t.NoError(err)
	t.NotNil(a)

	t.Error(o.Accounts().Delete("SYS"))
	t.NoError(o.SetSystemAccount(nil))
	sa, err := o.SystemAccount()
	t.Nil(err)
	t.Nil(sa)
	t.NoError(o.Accounts().Delete("SYS"))
}

func (t *ProviderSuite) Test_MemResolver() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	_, err = auth.Operators().Add("O")
	t.NoError(err)

	t.NoError(auth.Commit())

	auth, err = authb.NewAuth(t.Provider)
	t.NoError(err)

	o, err := auth.Operators().Get("O")
	t.NoError(err)

	_, err = o.MemResolver()
	t.NoError(err)
}

func (t *ProviderSuite) Test_OperatorImport() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	kp, err := authb.KeyFor(nkeys.PrefixByteOperator)
	t.NoError(err)

	oc := jwt.NewOperatorClaims(kp.Public)
	oc.Name = "O"
	skp, err := authb.KeyFor(nkeys.PrefixByteOperator)
	t.NoError(err)
	oc.SigningKeys.Add(skp.Public)

	token, err := oc.Encode(kp.Pair)
	t.NoError(err)

	o, err := auth.Operators().Import(
		[]byte(token),
		[]string{string(kp.Seed), string(skp.Seed)})
	t.NoError(err)
	t.NotNil(o)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())
	o, err = auth.Operators().Get("O")
	t.NoError(err)
	t.NotNil(o)
	t.Equal(kp.Public, o.Subject())
	t.Equal(skp.Public, o.SigningKeys().List()[0])
}

func (t *ProviderSuite) Test_Export() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	a := t.MaybeCreate(auth, "O", "A")
	u, err := a.Users().Add("U", a.Subject())
	t.NoError(err)
	t.NotNil(u)

	data, err := json.MarshalIndent(auth, "", "  ")
	t.NoError(err)
	// t.T().Log(string(data))

	sdir, err := os.MkdirTemp("/tmp", "stores")
	t.NoError(err)
	defer os.RemoveAll(sdir)

	kdir, err := os.MkdirTemp("/tmp", "keys")
	t.NoError(err)
	defer os.RemoveAll(kdir)

	auth2, err := authb.NewAuth(nsc.NewNscProvider(sdir, kdir))
	t.NoError(err)

	t.NoError(json.Unmarshal(data, &auth2))
	t.NoError(auth2.Commit())
	t.NoError(auth2.Reload())

	o, err := auth2.Operators().Get("O")
	t.NoError(err)
	a, err = o.Accounts().Get("A")
	t.NoError(err)
	_, err = a.Users().Get("U")
	t.NoError(err)
}

func (t *ProviderSuite) getEntity(auth *authb.AuthImpl, entity string) (authb.Tags, error) {
	elements := strings.Split(entity, "/")
	var err error
	var o authb.Operator
	var a authb.Account
	var u authb.User

	if len(elements) > 0 {
		o, err = auth.Operators().Get(elements[0])
		if err != nil && errors.Is(err, authb.ErrNotFound) {
			o, err = auth.Operators().Add(elements[0])
			t.NoError(err)
		}
	}
	if o != nil && len(elements) > 1 {
		a, err = o.Accounts().Get(elements[1])
		if err != nil && errors.Is(err, authb.ErrNotFound) {
			a, err = o.Accounts().Add(elements[1])
			t.NoError(err)
		}
	}

	if a != nil && len(elements) > 2 {
		u, err = a.Users().Get(elements[2])
		if err != nil && errors.Is(err, authb.ErrNotFound) {
			u, err = a.Users().Add(elements[2], "")
			t.NoError(err)
		}
	}

	switch len(elements) {
	case 1:
		t.NotNil(o)
		return o.Tags(), nil
	case 2:
		t.NotNil(a)
		return a.Tags(), nil
	case 3:
		t.NotNil(u)
		return u.Tags(), nil
	}

	return nil, fmt.Errorf("invalid entity: %s", entity)
}

func (t *ProviderSuite) Test_OperatorTags() {
	t.TagsCrud("O")
}

func (t *ProviderSuite) Test_AccountTags() {
	t.TagsCrud("O/A")
}

func (t *ProviderSuite) Test_UserTags() {
	t.TagsCrud("O/A/U")
}

func (t *ProviderSuite) TagsCrud(element string) {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	e, err := t.getEntity(auth, element)
	t.NoError(err)
	tags, err := e.All()
	t.NoError(err)
	t.Empty(tags)

	// cannot set empty or nil values
	t.Error(e.Add())
	t.Error(e.Add("  "))
	t.Error(e.Set())
	t.Error(e.Set("  "))

	// a tag
	t.NoError(e.Add("XxX"))
	// tags are lower case - but should be able to match
	t.True(e.Contains("xxx"))
	t.True(e.Contains("XxX"))

	// add preserves
	t.NoError(e.Add("y", "z"))

	t.True(e.Contains("xxx"))
	t.True(e.Contains("y"))
	t.True(e.Contains("z"))

	// removing something that doesn't exist is not an error, but reported
	ok, err := e.Remove("zz")
	t.NoError(err)
	t.False(ok)
	ok, err = e.Remove("y")
	t.NoError(err)
	t.True(ok)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	// should have values that were last set
	e, err = t.getEntity(auth, element)
	t.NoError(err)

	tags, err = e.All()
	t.NoError(err)
	t.Contains(tags, "xxx")
	t.Contains(tags, "z")
	t.NotContains(tags, "y")

	// replace all the tags
	t.NoError(e.Set("a", "b", "c"))
	tags, err = e.All()
	t.NoError(err)
	t.Len(tags, 3)
	t.Contains(tags, "a")
	t.Contains(tags, "b")
	t.Contains(tags, "c")

	// reload
	t.NoError(auth.Commit())
	t.NoError(auth.Reload())
	e, err = t.getEntity(auth, element)
	t.NoError(err)

	// check last values were saved
	tags, err = e.All()
	t.NoError(err)
	t.Len(tags, 3)
	t.Contains(tags, "a")
	t.Contains(tags, "b")
	t.Contains(tags, "c")

	// setting an empty list should succeed - nil is rejected
	t.NoError(e.Set([]string{}...))
	tags, err = e.All()
	t.NoError(err)
	t.Len(tags, 0)

	// reload
	t.NoError(auth.Commit())
	t.NoError(auth.Reload())
	e, err = t.getEntity(auth, element)
	t.NoError(err)
	tags, err = e.All()
	t.NoError(err)
	t.Len(tags, 0)
}
