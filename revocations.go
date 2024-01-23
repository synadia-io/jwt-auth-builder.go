package authb

import (
	"errors"
	"fmt"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"time"
)

var ErrRevocationPublicExportsNotAllowed = fmt.Errorf("public exports are not allowed")

type revocationTarget interface {
	getRevocationPrefix() nkeys.PrefixByte
	getRevocations() jwt.RevocationList
	update() error
}

type revocations struct {
	data revocationTarget
}

func (b *revocations) toRevocation(r Revocation) (*revocation, error) {
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

func (b *revocations) add(r Revocation) error {
	rr, err := b.toRevocation(r)
	if err != nil {
		return err
	}
	if rr.before.IsZero() {
		rr.before = time.Now()
	}

	if err = b.checkKey(rr.publicKey); err != nil {
		return err
	}

	b.data.getRevocations().Revoke(rr.publicKey, rr.before)
	return nil
}

func (b *revocations) checkKey(key string) error {
	if key == "*" {
		return nil
	}
	if _, err := KeyFrom(key, b.data.getRevocationPrefix()); err != nil {
		return err
	}
	return nil
}

func (b *revocations) Add(r Revocation) error {
	if err := b.add(r); err != nil {
		return err
	}
	return b.data.update()
}

func (b *revocations) Clear(r Revocation) (bool, error) {
	rr, err := b.toRevocation(r)
	if err != nil {
		return false, err
	}
	_, ok := b.data.getRevocations()[rr.publicKey]
	if !ok {
		// not found
		return false, nil
	}
	delete(b.data.getRevocations(), rr.publicKey)
	if err = b.data.update(); err != nil {
		return false, err
	}
	return true, nil
}

func (b *revocations) Compact() ([]Revocation, error) {
	found := b.data.getRevocations().MaybeCompact()
	if found == nil {
		return nil, nil
	}
	var buf []Revocation
	for _, e := range found {
		buf = append(buf, &revocation{publicKey: e.PublicKey, before: time.Unix(e.TimeStamp, 0)})
	}
	if err := b.data.update(); err != nil {
		return nil, err
	}
	return buf, nil
}

func (b *revocations) List() []Revocation {
	var buf []Revocation
	for k, e := range b.data.getRevocations() {
		buf = append(buf, &revocation{publicKey: k, before: time.Unix(e, 0)})
	}
	return buf
}

func (b *revocations) SetRevocations(revocations []Revocation) error {
	for k, _ := range b.data.getRevocations() {
		delete(b.data.getRevocations(), k)
	}
	for _, r := range revocations {
		if err := b.add(r); err != nil {
			return err
		}
	}
	return b.data.update()
}

func (b *revocations) HasRevocation(key string) (bool, error) {
	if err := b.checkKey(key); err != nil {
		return false, err
	}
	_, ok := b.data.getRevocations()[key]
	return ok, nil
}
