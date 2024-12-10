package kv

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/jsm.go/natscontext"
	jwt "github.com/nats-io/jwt/v2"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	ab "github.com/synadia-io/jwt-auth-builder.go"
)

// KvProvider is an AuthProvider that stores data in a JetStream KeyValue store
// The data is stored in the following format:
// Operators "O.<operatorPublicKey>" -> operator JWT
// Accounts "<operatorPublicKey>.<accountPublicKey>" -> account JWT
// Users "<accountPublicKey>.<userPublicKey>" -> user JWT
// Keys "keys.<publicKey>" -> seeds
// The required arguments are a natsURL, bucket name, and an optional encryption key.
// if an optional encryption key (an nkey CurveKeys) is used, the keys will be encrypted
// and require the same key to be decrypted.
type KvProvider struct {
	Bucket     string
	Nc         *nats.Conn
	Js         jetstream.JetStream
	Kv         jetstream.KeyValue
	EncryptKey nkeys.KeyPair
}

const (
	OperatorPrefix = "O"
)

type KvProviderOptions struct {
	NatsContext string
	NatsOptions []nats.Option
	Bucket      string
	EncryptKey  string
}

type KvProviderOption func(*KvProviderOptions) error

func Bucket(bucket string) KvProviderOption {
	return func(o *KvProviderOptions) error {
		o.Bucket = bucket
		return nil
	}
}

func NatsOptions(url string, options ...nats.Option) KvProviderOption {
	return func(o *KvProviderOptions) error {
		var buf []nats.Option
		for _, o := range options {
			if o != nil {
				buf = append(buf, o)
			}
		}
		o.NatsOptions = buf
		if url != "" {
			o.NatsOptions = append(o.NatsOptions, func(options *nats.Options) error {
				options.Url = strings.TrimSpace(url)
				return nil
			})
		}
		return nil
	}
}

func NatsContext(context string) KvProviderOption {
	return func(o *KvProviderOptions) error {
		o.NatsContext = context
		return nil
	}
}

func EncryptKey(key string) KvProviderOption {
	return func(o *KvProviderOptions) error {
		o.EncryptKey = key
		return nil
	}
}

func NewKvProvider(opts ...KvProviderOption) (*KvProvider, error) {
	var err error
	config := &KvProviderOptions{}
	for _, o := range opts {
		if err := o(config); err != nil {
			return nil, err
		}
	}
	var nc *nats.Conn
	name := config.NatsContext
	if name != "" {
		nc, err = natscontext.Connect(name, config.NatsOptions...)
		if err != nil {
			return nil, err
		}
	} else if len(config.NatsOptions) > 0 {
		options := &nats.Options{}
		for _, o := range config.NatsOptions {
			if err := o(options); err != nil {
				return nil, err
			}
		}
		nc, err = options.Connect()
		if err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	return NewKvProviderWithConnection(nc, config.Bucket, config.EncryptKey)
}

func NewKvProviderWithConnection(nc *nats.Conn, bucket string, encrypt string) (*KvProvider, error) {
	p := &KvProvider{Bucket: bucket}
	p.Nc = nc
	if encrypt != "" {
		kp, err := nkeys.FromCurveSeed([]byte(encrypt))
		if err != nil {
			return nil, err
		}
		p.EncryptKey = kp
	}
	if err := p.init(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *KvProvider) init() error {
	var err error
	js, err := jetstream.New(p.Nc)
	if err != nil {
		p.Disconnect()
		return err
	}
	p.Js = js
	_, err = p.Js.AccountInfo(context.Background())
	if err != nil {
		p.Disconnect()
		return err
	}
	p.Kv, err = p.Js.KeyValue(context.Background(), p.Bucket)
	if err != nil {
		if errors.Is(err, jetstream.ErrBucketNotFound) {
			p.Kv, err = p.Js.CreateKeyValue(context.Background(), jetstream.KeyValueConfig{
				Bucket: p.Bucket,
			})
			if err != nil {
				p.Disconnect()
				return err
			}
		} else if err != nil {
			p.Disconnect()
			return err
		}
	}
	return nil
}

func (p *KvProvider) Disconnect() {
	p.Nc.Close()
}

// GetChildren returns entities are stored under <prefix>.<childPublicKey>
func (p *KvProvider) GetChildren(prefix string) (map[string][]byte, error) {
	entries, err := p.Kv.History(context.Background(), fmt.Sprintf("%s.*", prefix))
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, err
	}

	m := make(map[string][]byte)
	for _, e := range entries {
		if e.Operation() != jetstream.KeyValuePut {
			delete(m, e.Key())
			continue
		} else {
			n := e.Key()[len(prefix)+1:]
			m[n] = e.Value()
		}
	}
	return m, nil
}

func (p *KvProvider) Load() ([]*ab.OperatorData, error) {
	datas, err := p.LoadOperators()
	if err != nil {
		return nil, err
	}
	for _, v := range datas {
		if err := p.LoadAccounts(v); err != nil {
			return nil, err
		}
		for _, a := range v.AccountDatas {
			if err := p.LoadUsers(a); err != nil {
				return nil, err
			}
		}
	}
	return datas, nil
}

func (p *KvProvider) LoadOperators() ([]*ab.OperatorData, error) {
	m, err := p.GetChildren(OperatorPrefix)
	if err != nil {
		return nil, err
	}
	operators := make([]*ab.OperatorData, 0, len(m))
	for _, v := range m {
		o := &ab.OperatorData{
			BaseData: ab.BaseData{
				Token: string(v),
			},
		}
		oc, err := jwt.DecodeOperatorClaims(o.Token)
		if err != nil {
			return nil, err
		}
		o.Claim = oc
		o.Modified = false
		o.Loaded = o.Claim.IssuedAt
		o.EntityName = o.Claim.Name
		o.Key, err = p.GetKey(o.Claim.Subject)
		if err != nil {
			return nil, err
		}
		for _, sk := range o.Claim.SigningKeys {
			k, err := p.GetKey(sk)
			if err != nil {
				return nil, err
			}
			o.OperatorSigningKeys = append(o.OperatorSigningKeys, k)
		}
		operators = append(operators, o)
	}
	return operators, nil
}

func (p *KvProvider) LoadAccounts(od *ab.OperatorData) error {
	// accounts stored under <operatorPublicKey>.<accountPublicKey>
	m, err := p.GetChildren(od.Claim.Subject)
	if err != nil {
		return err
	}
	for _, v := range m {
		a := &ab.AccountData{
			Operator: od,
			BaseData: ab.BaseData{
				Token: string(v),
			},
		}
		ac, err := jwt.DecodeAccountClaims(a.Token)
		if err != nil {
			return err
		}
		a.Modified = false
		a.Claim = ac
		a.Loaded = a.Claim.IssuedAt
		a.EntityName = a.Claim.Name
		a.Key, err = p.GetKey(a.Claim.Subject)
		if err != nil {
			return err
		}
		for pk := range a.Claim.SigningKeys {
			k, err := p.GetKey(pk)
			if err != nil {
				return err
			}
			a.AccountSigningKeys = append(a.AccountSigningKeys, k)
		}
		od.AccountDatas = append(od.AccountDatas, a)
	}
	return nil
}

func (p *KvProvider) LoadUsers(ad *ab.AccountData) error {
	// users stored under <accountPublicKey>.<userPublicKey>
	m, err := p.GetChildren(ad.Claim.Subject)
	if err != nil {
		return err
	}
	for _, v := range m {
		u := &ab.UserData{
			AccountData: ad,
			BaseData: ab.BaseData{
				Token: string(v),
			},
		}
		uc, err := jwt.DecodeUserClaims(u.Token)
		if err != nil {
			return err
		}
		u.Claim = uc
		u.Modified = false
		u.Loaded = u.Claim.IssuedAt
		u.EntityName = u.Claim.Name
		u.Key, err = p.GetKey(u.Claim.Subject)
		if err != nil {
			return err
		}

		ad.UserDatas = append(ad.UserDatas, u)
	}
	return nil
}

func (p *KvProvider) GetKey(pk string) (*ab.Key, error) {
	e, err := p.Kv.Get(context.Background(), fmt.Sprintf("keys.%s", pk))
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, nil
	}
	value := e.Value()
	if p.EncryptKey != nil {
		pk, err := p.EncryptKey.PublicKey()
		if err != nil {
			return nil, err
		}
		value, err = p.EncryptKey.Open(value, pk)
		if err != nil {
			return nil, err
		}
	}
	seed := string(value)
	return ab.KeyFrom(seed)
}

func (p *KvProvider) PutKey(key *ab.Key) error {
	v := key.Seed
	if p.EncryptKey != nil {
		pk, err := p.EncryptKey.PublicKey()
		if err != nil {
			return err
		}
		v, err = p.EncryptKey.Seal(v, pk)
		if err != nil {
			return err
		}
	}
	_, err := p.Kv.Put(context.Background(), fmt.Sprintf("keys.%s", key.Public), v)
	return err
}

func (p *KvProvider) DeleteKey(key string) error {
	return p.Kv.Delete(context.Background(), fmt.Sprintf("keys.%s", key))
}

func (p *KvProvider) Store(operators []*ab.OperatorData) error {
	for _, o := range operators {
		if err := p.StoreOperator(o); err != nil {
			return err
		}

		for _, a := range o.AccountDatas {
			if err := p.StoreAccount(a); err != nil {
				return err
			}
			for _, u := range a.UserDatas {
				if u.Ephemeral {
					continue
				}
				if err := p.StoreUser(u); err != nil {
					return err
				}
			}
			for _, u := range a.DeletedUsers {
				if err := p.DeleteUser(u); err != nil {
					return err
				}
			}
			a.DeletedUsers = nil
		}

		for _, k := range o.AddedKeys {
			if err := p.PutKey(k); err != nil {
				return err
			}
		}
		for _, k := range o.DeletedKeys {
			if err := p.DeleteKey(k); err != nil {
				return err
			}
		}
		for _, a := range o.DeletedAccounts {
			if err := p.DeleteAccount(a); err != nil {
				return err
			}
			for _, u := range a.UserDatas {
				if err := p.DeleteUser(u); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (p *KvProvider) StoreOperator(o *ab.OperatorData) error {
	if !o.Modified {
		return nil
	}
	_, err := p.Kv.Put(context.Background(), fmt.Sprintf("%s.%s", OperatorPrefix, o.Subject()), []byte(o.Token))
	if err != nil {
		return err
	}
	if err := p.PutKey(o.Key); err != nil {
		return err
	}
	for _, k := range o.OperatorSigningKeys {
		if err := p.PutKey(k); err != nil {
			return err
		}
	}
	o.Loaded = o.Claim.IssuedAt
	o.Modified = false
	return nil
}

func (p *KvProvider) StoreAccount(a *ab.AccountData) error {
	if !a.Modified {
		return nil
	}
	_, err := p.Kv.Put(context.Background(),
		fmt.Sprintf("%s.%s", a.Operator.Subject(), a.Subject()),
		[]byte(a.Token))
	if err != nil {
		return err
	}
	if err := p.PutKey(a.Key); err != nil {
		return err
	}
	for _, k := range a.AccountSigningKeys {
		if err := p.PutKey(k); err != nil {
			return err
		}
	}
	a.Loaded = a.Claim.IssuedAt
	a.Modified = false
	return nil
}

func (p *KvProvider) StoreUser(u *ab.UserData) error {
	if !u.Modified {
		return nil
	}
	_, err := p.Kv.Put(context.Background(),
		fmt.Sprintf("%s.%s", u.AccountData.Subject(), u.Subject()),
		[]byte(u.Token))
	if err != nil {
		return err
	}
	u.Loaded = u.Claim.IssuedAt
	u.Modified = false
	return nil
}

func (p *KvProvider) DeleteAccount(a *ab.AccountData) error {
	return p.Kv.Delete(context.Background(), fmt.Sprintf("%s.%s", a.Operator.Subject(), a.Subject()))
}

func (p *KvProvider) DeleteUser(u *ab.UserData) error {
	return p.Kv.Delete(context.Background(), fmt.Sprintf("%s.%s", u.AccountData.Subject(), u.Subject()))
}

func (p *KvProvider) Destroy() error {
	return p.Js.DeleteKeyValue(context.Background(), p.Bucket)
}
