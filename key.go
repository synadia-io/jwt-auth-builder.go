package authb

import (
	"encoding/json"
	"fmt"

	"github.com/nats-io/nkeys"
)

type Key struct {
	Pair   nkeys.KeyPair
	Public string
	Seed   []byte
}

func (k *Key) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Key string `json:"key"`
	}{
		Key: string(k.Seed),
	})
}

func (k *Key) UnmarshalJSON(data []byte) error {
	var v struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	var err error
	k.Seed = []byte(v.Key)
	k.Pair, err = nkeys.FromSeed(k.Seed)
	if err != nil {
		return err
	}
	k.Public, err = k.Pair.PublicKey()
	return err
}

func KeyFromNkey(kp nkeys.KeyPair, check ...nkeys.PrefixByte) (*Key, error) {
	k := &Key{Pair: kp}
	var err error
	k.Public, err = kp.PublicKey()
	if err != nil {
		return nil, err
	}
	k.Seed, _ = kp.Seed()
	if len(check) > 0 {
		if err = nkeys.CompatibleKeyPair(kp, check...); err != nil {
			return nil, err
		}
	}
	return k, nil
}

func KeyFrom(key string, check ...nkeys.PrefixByte) (*Key, error) {
	k := &Key{}
	var err error
	if len(key) == 0 {
		return nil, fmt.Errorf("invalid key - empty string")
	}
	if key[0] == 'S' {
		k.Pair, err = nkeys.FromSeed([]byte(key))
		if err != nil {
			return nil, err
		}
		k.Seed, err = k.Pair.Seed()
		if err != nil {
			return nil, err
		}
	} else {
		k.Pair, err = nkeys.FromPublicKey(key)
		if err != nil {
			return nil, err
		}
	}
	if len(check) > 0 {
		if err = nkeys.CompatibleKeyPair(k.Pair, check...); err != nil {
			return nil, err
		}
	}
	k.Public, err = k.Pair.PublicKey()
	if err != nil {
		return nil, err
	}
	return k, nil
}

func KeyFor(p nkeys.PrefixByte) (*Key, error) {
	k := &Key{}
	var err error
	k.Pair, err = nkeys.CreatePair(p)
	if err != nil {
		return k, err
	}
	k.Seed, err = k.Pair.Seed()
	if err != nil {
		return k, err
	}
	k.Public, err = k.Pair.PublicKey()
	if err != nil {
		return k, err
	}
	return k, nil
}
