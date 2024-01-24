package authb

import (
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

var ErrRevocationPublicExportsNotAllowed = fmt.Errorf("public exports are not allowed")

func NewRevocationEntry(key string, before time.Time) RevocationEntry {
	return &revocation{publicKey: key, before: before}
}

type revocation struct {
	publicKey string
	before    time.Time
}

func (t *revocation) PublicKey() string {
	return t.publicKey
}

func (t *revocation) At() time.Time {
	return t.before
}

type revocationTarget interface {
	getRevocationPrefix() nkeys.PrefixByte
	getRevocations() jwt.RevocationList
	update() error
}

type revocations struct {
	data revocationTarget
}

func (b *revocations) toRevocation(r RevocationEntry) (*revocation, error) {
	if r == nil {
		return nil, errors.New("revocation cannot be nil")
	}
	rr, ok := r.(*revocation)
	if !ok {
		return nil, errors.New("invalid revocation")
	}
	if rr.publicKey == "" {
		return nil, errors.New("revocation target is not specified")
	}
	return rr, nil
}

func (b *revocations) checkKey(key string) (string, error) {
	if key == "*" {
		return "*", nil
	}
	pk, err := KeyFrom(key, b.data.getRevocationPrefix())
	if err != nil {
		return "", err
	}
	return pk.Public, nil
}

func (b *revocations) add(r RevocationEntry) error {
	rr, err := b.toRevocation(r)
	if err != nil {
		return err
	}
	return b.addRevocation(rr.publicKey, rr.before)
}

func (b *revocations) addRevocation(key string, before time.Time) error {
	k, err := b.checkKey(key)
	if err != nil {
		return err
	}
	if before.IsZero() {
		before = time.Now()
	}

	b.data.getRevocations().Revoke(k, before)
	return nil
}

func (b *revocations) Add(key string, at time.Time) error {
	if err := b.addRevocation(key, at); err != nil {
		return err
	}
	return b.data.update()
}

func (b *revocations) delete(key string) (bool, error) {
	pk, err := b.checkKey(key)
	if err != nil {
		return false, err
	}
	_, ok := b.data.getRevocations()[pk]
	if !ok {
		// not found
		return false, nil
	}
	delete(b.data.getRevocations(), pk)
	return true, nil
}

func (b *revocations) Delete(key string) (bool, error) {
	ok, err := b.delete(key)
	if ok {
		err = b.data.update()
	}
	return ok, err
}

func (b *revocations) Compact() ([]RevocationEntry, error) {
	found := b.data.getRevocations().MaybeCompact()
	if found == nil {
		return nil, nil
	}
	var buf []RevocationEntry
	for _, e := range found {
		buf = append(buf, &revocation{publicKey: e.PublicKey, before: time.Unix(e.TimeStamp, 0)})
	}
	if err := b.data.update(); err != nil {
		return nil, err
	}
	return buf, nil
}

func (b *revocations) List() []RevocationEntry {
	var buf []RevocationEntry
	for k, e := range b.data.getRevocations() {
		buf = append(buf, &revocation{publicKey: k, before: time.Unix(e, 0)})
	}
	return buf
}

func (b *revocations) Set(revocations []RevocationEntry) error {
	for k := range b.data.getRevocations() {
		delete(b.data.getRevocations(), k)
	}
	for _, r := range revocations {
		if err := b.add(r); err != nil {
			return err
		}
	}
	return b.data.update()
}

func (b *revocations) Contains(key string) (bool, error) {
	k, err := b.checkKey(key)
	if err != nil {
		return false, err
	}
	_, ok := b.data.getRevocations()[k]
	return ok, nil
}
