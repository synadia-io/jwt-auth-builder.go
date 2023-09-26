package tests

import (
	"errors"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/require"
	"github.com/synadia-io/jwt-auth-builder.go"
	"github.com/synadia-io/jwt-auth-builder.go/providers/kv"

	"testing"
)

type KvStore struct {
	provider *kv.KvProvider
	t        *testing.T
}

func NewKvStore(t *testing.T) *KvStore {
	ts := &KvStore{}
	ts.t = t
	return ts
}

func (ts *KvStore) KeyExists(k string) bool {
	v, err := ts.provider.GetKey(k)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return false
	}
	return v != nil
}

func (ts *KvStore) GetKey(k string) *nats_auth.Key {
	v, err := ts.provider.GetKey(k)
	require.NoError(ts.t, err)
	return v
}

func (ts *KvStore) OperatorExists(name string) bool {
	// FIXME: should have a way of listing operators by name
	operators, err := ts.provider.LoadOperators()
	require.NoError(ts.t, err)
	for _, o := range operators {
		if o.Name() == name {
			return true
		}
	}
	return false
}

func (ts *KvStore) GetOperator(name string) *jwt.OperatorClaims {
	var v *nats_auth.OperatorData
	operators, err := ts.provider.LoadOperators()
	for _, o := range operators {
		if o.Name() == name || o.Subject() == name {
			v = o
			break
		}
	}
	oc, err := jwt.DecodeOperatorClaims(v.Token)
	require.NoError(ts.t, err)
	return oc
}

func (ts *KvStore) AccountExists(operator string, name string) bool {
	operators, err := ts.provider.Load()
	require.NoError(ts.t, err)
	for _, o := range operators {
		if o.Name() == operator || o.Subject() == operator {
			for _, a := range o.AccountDatas {
				if a.Name() == name || a.Subject() == name {
					return true
				}
			}
		}
	}
	return false
}

func (ts *KvStore) GetAccount(operator string, name string) *jwt.AccountClaims {
	operators, err := ts.provider.Load()
	require.NoError(ts.t, err)
	for _, o := range operators {
		if o.Name() == operator || o.Subject() == operator {
			for _, a := range o.AccountDatas {
				if a.Name() == name || a.Subject() == name {
					return a.Claim
				}
			}
		}
	}
	return nil
}

func (ts *KvStore) UserExists(operator string, account string, name string) bool {
	operators, err := ts.provider.Load()
	require.NoError(ts.t, err)
	for _, o := range operators {
		if o.Name() == operator || o.Subject() == operator {
			for _, a := range o.AccountDatas {
				if a.Name() == account || a.Subject() == account {
					for _, u := range a.UserDatas {
						if u.Name() == name || u.Subject() == name {
							return true
						}
					}
				}
			}
		}
	}
	return false

}

func (ts *KvStore) GetUser(operator string, account string, name string) *jwt.UserClaims {
	operators, err := ts.provider.Load()
	require.NoError(ts.t, err)
	for _, o := range operators {
		if o.Name() == operator || o.Subject() == operator {
			for _, a := range o.AccountDatas {
				if a.Name() == account || a.Subject() == account {
					for _, u := range a.UserDatas {
						if u.Name() == name || u.Subject() == name {
							return u.Claim
						}
					}
				}
			}
		}
	}
	return nil
}

func (ts *KvStore) Cleanup() {
	require.NoError(ts.t, ts.provider.Destroy())
}
