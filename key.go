package nats_auth

import (
	"github.com/nats-io/nkeys"
)

type Key struct {
	Pair   nkeys.KeyPair
	Public string
	Seed   []byte
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
