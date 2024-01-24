package authb

import (
	"errors"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

type ServiceExportImpl struct {
	baseExportImpl
}

func NewService(name string, subject string) (ServiceExport, error) {
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	if subject == "" {
		return nil, errors.New("subject cannot be empty")
	}

	return &ServiceExportImpl{
		baseExportImpl{
			data:   nil,
			export: &jwt.Export{Name: name, Subject: jwt.Subject(subject), Type: jwt.Service},
		},
	}, nil
}

type StreamExportImpl struct {
	baseExportImpl
}

func NewStream(name string, subject string) (StreamExport, error) {
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	if subject == "" {
		return nil, errors.New("subject cannot be empty")
	}

	return &StreamExportImpl{
		baseExportImpl{
			data:   nil,
			export: &jwt.Export{Name: name, Subject: jwt.Subject(subject), Type: jwt.Service},
		},
	}, nil
}

type baseExportImpl struct {
	data   *AccountData
	export *jwt.Export
}

func (b *baseExportImpl) update() error {
	if b.data == nil {
		// this is an unbounded export
		return nil
	}
	if !b.export.TokenReq && len(b.export.Revocations) > 0 {
		return ErrRevocationPublicExportsNotAllowed
	}
	if err := b.data.update(); err != nil {
		return err
	}
	// update regenerated the claim, reload the reference
	if b.export.IsService() {
		e := b.data.getService(string(b.export.Subject))
		if e == nil {
			return errors.New("could not find service")
		}
		b.export = e.(*ServiceExportImpl).export
	} else if b.export.IsStream() {
		e := b.data.getStream(string(b.export.Subject))
		if e == nil {
			return errors.New("could not find stream")
		}
		b.export = e.(*StreamExportImpl).export
	} else {
		return errors.New("not implemented")
	}
	return nil
}

func (b *baseExportImpl) Name() string {
	return b.export.Name
}

func (b *baseExportImpl) SetName(n string) error {
	b.export.Name = n
	return b.update()
}

func (b *baseExportImpl) Subject() string {
	return string(b.export.Subject)
}

func (b *baseExportImpl) SetSubject(subject string) error {
	b.export.Subject = jwt.Subject(subject)
	return b.update()
}

func (b *baseExportImpl) TokenRequired() bool {
	return b.export.TokenReq
}

func (b *baseExportImpl) SetTokenRequired(tf bool) error {
	b.export.TokenReq = tf
	return b.update()
}

func (b *baseExportImpl) getRevocations() jwt.RevocationList {
	if b.export.Revocations == nil {
		b.export.Revocations = jwt.RevocationList{}
	}
	return b.export.Revocations
}

func (b *baseExportImpl) getRevocationPrefix() nkeys.PrefixByte {
	return nkeys.PrefixByteAccount
}

func (b *baseExportImpl) Revocations() Revocations {
	return &revocations{data: b}
}
