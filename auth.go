package authb

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

type KeysFn func(p nkeys.PrefixByte) (*Key, error)

type Options struct {
	SignFn jwt.SignFn
	KeysFn KeysFn
}

type IssuingService interface {
	Sign(c jwt.Claims, key *Key) (string, error)
	NewKey(prefixByte nkeys.PrefixByte) (*Key, error)
}

type AuthImpl struct {
	provider  AuthProvider
	operators []*OperatorData
	opts      *Options
}

func NewAuth(provider AuthProvider) (*AuthImpl, error) {
	return NewAuthWithOptions(provider, nil)
}

func NewAuthWithOptions(provider AuthProvider, opts *Options) (*AuthImpl, error) {
	if opts == nil {
		opts = &Options{}
	}
	// initialize default key provider
	if opts.KeysFn == nil {
		opts.KeysFn = KeyFor
	}

	auth := &AuthImpl{provider: provider, opts: opts}
	auth.provider = provider
	operators, err := auth.provider.Load()
	if err != nil {
		return nil, err
	}
	auth.operators = operators
	auth.initSigningService()
	return auth, nil
}

func (a *AuthImpl) initSigningService() {
	for _, op := range a.operators {
		op.SigningService = a
	}
}

func (a *AuthImpl) Sign(c jwt.Claims, key *Key) (string, error) {
	kp := key.Pair
	if a.opts.SignFn != nil {
		var err error
		kp, err = nkeys.FromPublicKey(key.Public)
		if err != nil {
			return "", err
		}
	}
	return c.EncodeWithSigner(kp, a.opts.SignFn)
}

func (a *AuthImpl) NewKey(prefixByte nkeys.PrefixByte) (*Key, error) {
	return a.opts.KeysFn(prefixByte)
}

type OperatorsImpl struct {
	auth *AuthImpl
}

func (a *AuthImpl) MarshalJSON() ([]byte, error) {
	return json.MarshalIndent(&struct {
		Operators []*OperatorData `json:"operators"`
	}{
		Operators: a.operators,
	}, "", "  ")
}

func (a *AuthImpl) UnmarshalJSON(data []byte) error {
	var v struct {
		Operators []*OperatorData `json:"operators"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	a.operators = v.Operators
	return nil
}

func (a *AuthImpl) Operators() Operators {
	return &OperatorsImpl{auth: a}
}

func (a *OperatorsImpl) List() []Operator {
	v := make([]Operator, len(a.auth.operators))
	for i, o := range a.auth.operators {
		v[i] = o
	}
	return v
}

func (a *OperatorsImpl) Get(name string) (Operator, error) {
	for _, o := range a.auth.operators {
		if o.EntityName == name || o.Subject() == name {
			return o, nil
		}
	}
	return nil, ErrNotFound
}

func (a *OperatorsImpl) Add(name string) (Operator, error) {
	var err error
	data := &OperatorData{SigningService: a.auth}
	data.EntityName = name
	data.Key, err = data.SigningService.NewKey(nkeys.PrefixByteOperator)
	if err != nil {
		return nil, err
	}
	data.Claim = jwt.NewOperatorClaims(data.Key.Public)
	data.Claim.Name = name

	a.auth.operators = append(a.auth.operators, data)
	if err := data.update(); err != nil {
		return nil, err
	}
	return data, nil
}

func (a *OperatorsImpl) Delete(name string) error {
	idx := -1
	for i, op := range a.auth.operators {
		if op.EntityName == name || op.Subject() == name {
			idx = i
			break
		}
	}
	if idx != -1 {
		a.auth.operators[idx] = a.auth.operators[len(a.auth.operators)-1]
		a.auth.operators = a.auth.operators[:len(a.auth.operators)-1]
	}
	return nil
}

func (a *OperatorsImpl) Import(token []byte, keys []string) (Operator, error) {
	claim, err := jwt.DecodeOperatorClaims(string(token))
	if err != nil {
		return nil, err
	}

	// we require all the keys? - new NGS will not allow you to
	// edit configs via CLI, so this is not a problem?
	m := make(map[string]*Key, len(keys))
	for i, k := range keys {
		key, err := KeyFrom(k, nkeys.PrefixByteOperator, nkeys.PrefixByteSeed)
		if err != nil {
			return nil, fmt.Errorf("invalid seed at %d: %w", i, err)
		}
		if key.Public != claim.Subject && !claim.SigningKeys.Contains(key.Public) {
			return nil, fmt.Errorf("invalid seed %s: is not referenced by the operator", k)
		}
		m[key.Public] = key
	}
	if len(keys) != len(claim.SigningKeys)+1 {
		return nil, fmt.Errorf("not all keys are provided: %d", len(keys))
	}

	var ok bool
	data := &OperatorData{SigningService: a.auth}
	data.Claim = claim
	data.EntityName = claim.Name
	data.Key, ok = m[claim.Subject]
	if !ok {
		return nil, fmt.Errorf("%s was not provided", claim.Subject)
	}
	for _, k := range claim.SigningKeys {
		key, ok := m[k]
		if !ok {
			return nil, fmt.Errorf("%s was not provided", k)
		}
		data.OperatorSigningKeys = append(data.OperatorSigningKeys, key)
	}
	a.auth.operators = append(a.auth.operators, data)
	if err := data.update(); err != nil {
		return nil, err
	}
	return data, nil
}

func (a *AuthImpl) Commit() error {
	return a.provider.Store(a.operators)
}

func (a *AuthImpl) Reload() error {
	var err error
	a.operators, err = a.provider.Load()
	if err != nil {
		return err
	}
	a.initSigningService()
	return nil
}

func (b *BaseData) JWT() string {
	return b.Token
}

func isNil(T any) bool {
	return T == nil || reflect.ValueOf(T).IsNil()
}
