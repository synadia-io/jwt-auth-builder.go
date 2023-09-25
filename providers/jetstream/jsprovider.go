package jetstream

import (
	"context"
	"fmt"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	ab "github.com/synadia-io/jwt-auth-builder.go"
)

type Provider struct {
	natsURL    string
	bucket     string
	nc         *nats.Conn
	js         jetstream.JetStream
	kv         jetstream.KeyValue
	encryptKey nkeys.KeyPair
}

const (
	OperatorPrefix = "O"
)

func NewJetstreamProvider(natsURL string, bucket string, encrypt string) (ab.AuthProvider, error) {
	p := &Provider{natsURL: natsURL, bucket: bucket}
	if encrypt != "" {
		kp, err := nkeys.FromCurveSeed([]byte(encrypt))
		if err != nil {
			return nil, err
		}
		p.encryptKey = kp
	}
	if err := p.init(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Provider) init() error {
	var err error
	p.nc, err = nats.Connect(p.natsURL)
	if err != nil {
		return err
	}
	js, err := jetstream.New(p.nc)
	if err != nil {
		p.disconnect()
		return err
	}
	p.js = js
	_, err = p.js.AccountInfo(context.Background())
	if err != nil {
		p.disconnect()
		return err
	}
	p.kv, err = p.js.KeyValue(context.Background(), p.bucket)
	if err != nil {
		if err == jetstream.ErrBucketNotFound {
			p.kv, err = p.js.CreateKeyValue(context.Background(), jetstream.KeyValueConfig{
				Bucket: p.bucket,
			})
			if err != nil {
				p.disconnect()
				return err
			}
		} else if err != nil {
			p.disconnect()
			return err
		}
	}
	return nil
}

func (p *Provider) disconnect() {
	p.nc.Close()
}

// child entities are stored under <pk>.<childPublicKey>
func (p *Provider) getChildren(prefix string) (map[string][]byte, error) {
	entries, err := p.kv.History(context.Background(), fmt.Sprintf("%s.*", prefix))
	if err != nil {
		if err == jetstream.ErrKeyNotFound {
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

func (p *Provider) Load() ([]*ab.OperatorData, error) {
	m, err := p.getChildren(OperatorPrefix)
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
		o.Loaded = o.Claim.IssuedAt
		o.EntityName = o.Claim.Name
		o.Key, err = p.getKey(o.Claim.Subject)
		if err != nil {
			return nil, err
		}
		for _, sk := range o.Claim.SigningKeys {
			k, err := p.getKey(sk)
			if err != nil {
				return nil, err
			}
			o.OperatorSigningKeys = append(o.OperatorSigningKeys, k)
		}
		if err := p.loadAccounts(o); err != nil {
			return nil, err
		}
		operators = append(operators, o)
	}
	return operators, nil
}

func (p *Provider) loadAccounts(od *ab.OperatorData) error {
	// accounts stored under <operatorPublicKey>.<accountPublicKey>
	m, err := p.getChildren(od.Claim.Subject)
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
		a.Claim = ac
		a.Loaded = a.Claim.IssuedAt
		a.EntityName = a.Claim.Name
		a.Key, err = p.getKey(a.Claim.Subject)
		if err != nil {
			return err
		}
		for pk := range a.Claim.SigningKeys {
			k, err := p.getKey(pk)
			if err != nil {
				return err
			}
			a.AccountSigningKeys = append(a.AccountSigningKeys, k)
		}
		if err := p.loadUsers(a); err != nil {
			return err
		}
		od.AccountDatas = append(od.AccountDatas, a)
	}
	return nil
}

func (p *Provider) loadUsers(ad *ab.AccountData) error {
	// users stored under <accountPublicKey>.<userPublicKey>
	m, err := p.getChildren(ad.Claim.Subject)
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
		u.Loaded = u.Claim.IssuedAt
		u.EntityName = u.Claim.Name
		u.Key, err = p.getKey(u.Claim.Subject)
		if err != nil {
			return err
		}

		ad.UserDatas = append(ad.UserDatas, u)
	}
	return nil
}

func (p *Provider) getKey(pk string) (*ab.Key, error) {
	e, err := p.kv.Get(context.Background(), fmt.Sprintf("keys.%s", pk))
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, nil
	}
	value := e.Value()
	if p.encryptKey != nil {
		pk, err := p.encryptKey.PublicKey()
		if err != nil {
			return nil, err
		}
		value, err = p.encryptKey.Open(value, pk)
		if err != nil {
			return nil, err
		}
	}
	seed := string(value)
	return ab.KeyFrom(seed)
}

func (p *Provider) putKey(key *ab.Key) error {
	v := key.Seed
	if p.encryptKey != nil {
		pk, err := p.encryptKey.PublicKey()
		if err != nil {
			return err
		}
		v, err = p.encryptKey.Seal(v, pk)
		if err != nil {
			return err
		}
	}
	_, err := p.kv.Put(context.Background(), fmt.Sprintf("keys.%s", key.Public), v)
	return err
}

func (p *Provider) deleteKey(key string) error {
	return p.kv.Delete(context.Background(), fmt.Sprintf("keys.%s", key))
}

func (p *Provider) Store(operators []*ab.OperatorData) error {
	for _, o := range operators {
		if err := p.storeOperator(o); err != nil {
			return err
		}

		for _, a := range o.AccountDatas {
			if err := p.storeAccount(a); err != nil {
				return err
			}
			for _, u := range a.UserDatas {
				if err := p.storeUser(u); err != nil {
					return err
				}
			}
			for _, u := range a.DeletedUsers {
				if err := p.deleteUser(u); err != nil {
					return err
				}
			}
			a.DeletedUsers = nil
		}

		for _, k := range o.AddedKeys {
			if err := p.putKey(k); err != nil {
				return err
			}
		}
		for _, k := range o.DeletedKeys {
			if err := p.deleteKey(k); err != nil {
				return err
			}
		}
		for _, a := range o.DeletedAccounts {
			if err := p.deleteAccount(a); err != nil {
				return err
			}
			for _, u := range a.UserDatas {
				if err := p.deleteUser(u); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (p *Provider) storeOperator(o *ab.OperatorData) error {
	if o.Loaded > 0 && o.Loaded > o.Claim.IssuedAt {
		return nil
	}
	_, err := p.kv.Put(context.Background(), fmt.Sprintf("%s.%s", OperatorPrefix, o.Subject()), []byte(o.Token))
	if err != nil {
		return err
	}
	if err := p.putKey(o.Key); err != nil {
		return err
	}
	for _, k := range o.OperatorSigningKeys {
		if err := p.putKey(k); err != nil {
			return err
		}
	}
	o.Loaded = o.Claim.IssuedAt
	return nil
}

func (p *Provider) storeAccount(a *ab.AccountData) error {
	if a.Loaded > 0 && a.Loaded > a.Claim.IssuedAt {
		return nil
	}
	_, err := p.kv.Put(context.Background(),
		fmt.Sprintf("%s.%s", a.Operator.Subject(), a.Subject()),
		[]byte(a.Token))
	if err != nil {
		return err
	}
	if err := p.putKey(a.Key); err != nil {
		return err
	}
	for _, k := range a.AccountSigningKeys {
		if err := p.putKey(k); err != nil {
			return err
		}
	}
	a.Loaded = a.Claim.IssuedAt
	return nil
}

func (p *Provider) storeUser(u *ab.UserData) error {
	if u.Loaded > 0 && u.Loaded > u.Claim.IssuedAt {
		return nil
	}
	_, err := p.kv.Put(context.Background(),
		fmt.Sprintf("%s.%s", u.AccountData.Subject(), u.Subject()),
		[]byte(u.Token))
	if err != nil {
		return err
	}
	u.Loaded = u.Claim.IssuedAt
	return nil
}

func (p *Provider) deleteAccount(a *ab.AccountData) error {
	return p.kv.Delete(context.Background(), fmt.Sprintf("%s.%s", a.Operator.Subject(), a.Subject()))
}

func (p *Provider) deleteUser(u *ab.UserData) error {
	return p.kv.Delete(context.Background(), fmt.Sprintf("%s.%s", u.AccountData.Subject(), u.Subject()))
}
