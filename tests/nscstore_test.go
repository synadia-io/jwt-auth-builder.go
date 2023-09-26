package tests

import (
	"fmt"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/nats-io/nsc/v2/home"
	"github.com/stretchr/testify/require"
	"github.com/synadia-io/jwt-auth-builder.go"

	"os"
	"path/filepath"
	"testing"
)

type NscStore struct {
	root string
	t    *testing.T
}

func NewNscStore(t *testing.T) *NscStore {
	root := t.TempDir()
	ts := &NscStore{root: root, t: t}
	require.NoError(t, os.Mkdir(ts.StoresDir(), 0700))
	require.NoError(t, os.Mkdir(ts.KeysDir(), 0700))
	return ts
}

func (ts *NscStore) StoresDir() string {
	return filepath.Join(ts.root, home.StoresSubDirName)
}

func (ts *NscStore) KeysDir() string {
	return filepath.Join(ts.root, home.KeysSubDirName)
}

func (ts *NscStore) KeyExists(k string) bool {
	fp := filepath.Join(ts.KeysDir(), store.KeysDir, k[:1], k[1:3], fmt.Sprintf("%s%s", k, store.NKeyExtension))
	_, err := os.Stat(fp)
	return err == nil
}

func (ts *NscStore) GetKey(k string) *nats_auth.Key {
	fp := filepath.Join(ts.KeysDir(), store.KeysDir, k[:1], k[1:3], fmt.Sprintf("%s%s", k, store.NKeyExtension))
	d, err := os.ReadFile(fp)
	require.NoError(ts.t, err)
	key, err := nats_auth.KeyFrom(string(d))
	require.NoError(ts.t, err)
	return key
}

func (ts *NscStore) OperatorExists(name string) bool {
	fp := filepath.Join(ts.StoresDir(), name, fmt.Sprintf("%s.jwt", name))
	_, err := os.Stat(fp)
	return err == nil
}

func (ts *NscStore) GetOperator(name string) *jwt.OperatorClaims {
	fp := filepath.Join(ts.StoresDir(), name, store.JwtName(name))
	d, err := os.ReadFile(fp)
	require.NoError(ts.t, err)
	oc, err := jwt.DecodeOperatorClaims(string(d))
	require.NoError(ts.t, err)
	return oc
}

func (ts *NscStore) AccountExists(operator string, name string) bool {
	fp := filepath.Join(ts.StoresDir(), operator, store.Accounts, name, store.JwtName(name))
	_, err := os.Stat(fp)
	return err == nil
}

func (ts *NscStore) GetAccount(operator string, name string) *jwt.AccountClaims {
	fp := filepath.Join(ts.StoresDir(), operator, store.Accounts, name, store.JwtName(name))
	d, err := os.ReadFile(fp)
	require.NoError(ts.t, err)
	ac, err := jwt.DecodeAccountClaims(string(d))
	require.NoError(ts.t, err)
	return ac
}

func (ts *NscStore) UserExists(operator string, account string, name string) bool {
	fp := filepath.Join(ts.StoresDir(), operator, store.Accounts, account, store.Users, store.JwtName(name))
	_, err := os.Stat(fp)
	return err == nil
}

func (ts *NscStore) GetUser(operator string, account string, name string) *jwt.UserClaims {
	fp := filepath.Join(ts.StoresDir(), operator, store.Accounts, account, store.Users, store.JwtName(name))
	d, err := os.ReadFile(fp)
	require.NoError(ts.t, err)
	uc, err := jwt.DecodeUserClaims(string(d))
	require.NoError(ts.t, err)
	return uc
}

func (ts *NscStore) Cleanup() {
}
