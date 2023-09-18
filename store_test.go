package nats_auth

import (
	"fmt"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/nats-io/nsc/v2/home"
	"github.com/stretchr/testify/require"

	"os"
	"path/filepath"
	"testing"
)

type TestStore struct {
	root string
}

func NewTestStore(t *testing.T) *TestStore {
	root := t.TempDir()
	ts := &TestStore{root: root}
	require.NoError(t, os.Mkdir(ts.StoresDir(), 0700))
	require.NoError(t, os.Mkdir(ts.KeysDir(), 0700))
	return ts
}

func (ts *TestStore) StoresDir() string {
	return filepath.Join(ts.root, home.StoresSubDirName)
}

func (ts *TestStore) KeysDir() string {
	return filepath.Join(ts.root, home.KeysSubDirName)
}

func (ts *TestStore) KeyExists(t *testing.T, k string) bool {
	fp := filepath.Join(ts.KeysDir(), store.KeysDir, k[:1], k[1:3], fmt.Sprintf("%s%s", k, store.NKeyExtension))
	_, err := os.Stat(fp)
	return err == nil
}

func (ts *TestStore) GetKey(t *testing.T, k string) *Key {
	fp := filepath.Join(ts.KeysDir(), store.KeysDir, k[:1], k[1:3], fmt.Sprintf("%s%s", k, store.NKeyExtension))
	d, err := os.ReadFile(fp)
	require.NoError(t, err)
	key, err := KeyFrom(string(d))
	require.NoError(t, err)
	return key
}

func (ts *TestStore) OperatorExists(name string) bool {
	fp := filepath.Join(ts.StoresDir(), name, fmt.Sprintf("%s.jwt", name))
	_, err := os.Stat(fp)
	return err == nil
}

func (ts *TestStore) GetOperator(t *testing.T, name string) *jwt.OperatorClaims {
	fp := filepath.Join(ts.StoresDir(), name, store.JwtName(name))
	d, err := os.ReadFile(fp)
	require.NoError(t, err)
	oc, err := jwt.DecodeOperatorClaims(string(d))
	require.NoError(t, err)
	return oc
}

func (ts *TestStore) AccountExists(operator string, name string) bool {
	fp := filepath.Join(ts.StoresDir(), operator, store.Accounts, name, store.JwtName(name))
	_, err := os.Stat(fp)
	return err == nil
}

func (ts *TestStore) GetAccount(t *testing.T, operator string, name string) *jwt.AccountClaims {
	fp := filepath.Join(ts.StoresDir(), operator, store.Accounts, name, store.JwtName(name))
	d, err := os.ReadFile(fp)
	require.NoError(t, err)
	ac, err := jwt.DecodeAccountClaims(string(d))
	require.NoError(t, err)
	return ac
}

func (ts *TestStore) UserExists(operator string, account string, name string) bool {
	fp := filepath.Join(ts.StoresDir(), operator, store.Accounts, account, store.Users, store.JwtName(name))
	_, err := os.Stat(fp)
	return err == nil
}

func (ts *TestStore) GetUser(t *testing.T, operator string, account string, name string) *jwt.UserClaims {
	fp := filepath.Join(ts.StoresDir(), operator, store.Accounts, account, store.Users, store.JwtName(name))
	d, err := os.ReadFile(fp)
	require.NoError(t, err)
	uc, err := jwt.DecodeUserClaims(string(d))
	require.NoError(t, err)
	return uc
}
