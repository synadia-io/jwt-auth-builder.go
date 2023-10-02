package tests

import (
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nuid"
	"github.com/stretchr/testify/suite"
	nats_auth "github.com/synadia-io/jwt-auth-builder.go"
	"github.com/synadia-io/jwt-auth-builder.go/providers/kv"
	"github.com/synadia-io/jwt-auth-builder.go/providers/nsc"
	"testing"
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
	Store    TestStore
	cleanup  func(t *testing.T)
	suite.Suite
}

func (suite *ProviderSuite) SetupTest() {
	switch suite.Kind {
	case NscProvider:
		ts := NewNscStore(suite.T())
		suite.Store = ts
		suite.Provider = nsc.NewNscProvider(ts.StoresDir(), ts.KeysDir())
	case KvProvider:
		ts := NewKvStore(suite.T())
		suite.Store = ts
		k, err := kv.NewKvProvider(kv.NatsOptions("demo.nats.io:4222",
			nil),
			kv.Bucket(nuid.Next()),
			kv.EncryptKey(""))
		suite.Require().NoError(err)
		suite.Provider = k
		ts.provider = k
		suite.cleanup = func(t *testing.T) {
			ts.Cleanup()
		}
	default:
		suite.FailNow("unknown provider type")
	}
}

func (suite *ProviderSuite) TearDownTest() {
	if suite.cleanup != nil {
		suite.cleanup(suite.T())
	}
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
