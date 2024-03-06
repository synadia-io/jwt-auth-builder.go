package tests

import (
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nuid"
	"github.com/stretchr/testify/suite"
	nats_auth "github.com/synadia-io/jwt-auth-builder.go"
	"github.com/synadia-io/jwt-auth-builder.go/providers/kv"
	"github.com/synadia-io/jwt-auth-builder.go/providers/nsc"
)

type ProviderType uint8

const (
	NscProvider ProviderType = iota
	KvProvider
)

type TestStore interface {
	KeyExists(k string) bool
	GetKey(k string) *nats_auth.Key
	OperatorExists(name string) bool
	GetOperator(name string) *jwt.OperatorClaims
	AccountExists(operator string, name string) bool
	GetAccount(operator string, name string) *jwt.AccountClaims
	UserExists(operator string, account string, name string) bool
	GetUser(operator string, account string, name string) *jwt.UserClaims

	Cleanup()
}

type ProviderSuite struct {
	Kind     ProviderType
	Provider nats_auth.AuthProvider
	NS       *NatsServer
	Store    TestStore
	cleanup  func(t *testing.T)
	suite.Suite
}

func (t *ProviderSuite) SetupTest() {
	switch t.Kind {
	case NscProvider:
		ts := NewNscStore(t.T())
		t.Store = ts
		t.Provider = nsc.NewNscProvider(ts.StoresDir(), ts.KeysDir())
	case KvProvider:
		t.NS = NewNatsServer(t.T(), nil)
		ts := NewKvStore(t.T())
		t.Store = ts
		k, err := kv.NewKvProvider(kv.NatsOptions(t.NS.Url),
			kv.Bucket(nuid.Next()),
			kv.EncryptKey(""))
		t.Require().NoError(err)
		t.Provider = k
		ts.provider = k
		t.cleanup = func(tt *testing.T) {
			ts.Cleanup()
			if t.NS != nil {
				t.NS.Server.Shutdown()
			}
		}
	default:
		t.FailNow("unknown provider type")
	}
}

func (t *ProviderSuite) TearDownTest() {
	if t.cleanup != nil {
		t.cleanup(t.T())
	}
}

func (t *ProviderSuite) GetAccount(auth nats_auth.Auth, operator string, account string) nats_auth.Account {
	o, err := auth.Operators().Get(operator)
	t.NoError(err)

	a, err := o.Accounts().Get(account)
	t.NoError(err)
	return a
}

func (t *ProviderSuite) MaybeCreate(auth nats_auth.Auth, operator string, account string) nats_auth.Account {
	var err error
	o, err := auth.Operators().Get(operator)
	if err != nil {
		t.ErrorIs(err, nats_auth.ErrNotFound)
		o, err = auth.Operators().Add(operator)
		t.NoError(err)
	}
	a, err := o.Accounts().Add(account)
	t.NoError(err)
	t.NotNil(a)
	return a
}

func (t *ProviderSuite) UserKey() *nats_auth.Key {
	k, err := nats_auth.KeyFor(nkeys.PrefixByteUser)
	t.Require().NoError(err)
	return k
}

func (t *ProviderSuite) AccountKey() *nats_auth.Key {
	k, err := nats_auth.KeyFor(nkeys.PrefixByteAccount)
	t.Require().NoError(err)
	return k
}

func Test_NscProvider(t *testing.T) {
	a := new(ProviderSuite)
	a.Kind = NscProvider
	suite.Run(t, a)
}

func Test_KvProvider(t *testing.T) {
	a := new(ProviderSuite)
	a.Kind = KvProvider
	suite.Run(t, a)
}
