package tests

import (
	"fmt"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	authb "github.com/synadia-io/jwt-auth-builder.go"
	nsc "github.com/synadia-io/jwt-auth-builder.go/providers/nsc"
	"testing"
)

func TestExternal(v *testing.T) {
	t := assert.New(v)

	store := NewNscStore(v)
	defer store.Cleanup()
	p := nsc.NewNscProvider(store.StoresDir(), store.KeysDir())

	keys := make(map[string]nkeys.KeyPair)
	signFn := func(pub string, data []byte) ([]byte, error) {
		kp := keys[pub]
		if kp == nil {
			return nil, fmt.Errorf("secret key not found %s", pub)
		}
		return kp.Sign(data)
	}
	keysFn := func(p nkeys.PrefixByte) (*authb.Key, error) {
		k, err := authb.KeyFor(p)
		if err != nil {
			return nil, err
		}

		pub, err := authb.KeyFrom(k.Public)
		if err != nil {
			return nil, err
		}
		keys[k.Public] = k.Pair
		return pub, nil
	}

	opts := &authb.Options{KeysFn: keysFn, SignFn: signFn}
	auth, err := authb.NewAuthWithOptions(p, opts)

	t.NoError(err)
	o, err := auth.Operators().Add("O")
	t.NoError(err)
	a, err := o.Accounts().Add("A")
	t.NoError(err)
	u, err := a.Users().Add("U", "")
	t.NoError(err)
	t.NotNil(u)

	t.Len(keys, 3)
}
