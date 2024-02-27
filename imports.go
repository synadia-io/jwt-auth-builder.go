package authb

import (
	"errors"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func newImport(name string, account string, subject string, et jwt.ExportType) (*jwt.Import, error) {
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	if subject == "" {
		return nil, errors.New("subject cannot be empty")
	}
	ak, err := KeyFrom(account, nkeys.PrefixByteAccount)
	if err != nil {
		return nil, err
	}
	return &jwt.Import{
		Name:    name,
		Subject: jwt.Subject(subject),
		Account: ak.Public,
		Type:    et,
	}, nil
}

func NewServiceImport(name string, account string, subject string) (ServiceImport, error) {
	im, err := newImport(name, account, subject, jwt.Service)
	if err != nil {
		return nil, err
	}
	return &ServiceImportImpl{
		baseImportImpl{
			data: nil,
			in:   im,
		},
	}, nil
}

func NewStreamImport(name string, account string, subject string) (StreamImport, error) {
	im, err := newImport(name, account, subject, jwt.Stream)
	if err != nil {
		return nil, err
	}

	return &StreamImportImpl{
		baseImportImpl{
			data: nil,
			in:   im,
		},
	}, nil
}

type baseImportImpl struct {
	data *AccountData
	in   *jwt.Import
}

type ServiceImportImpl struct {
	baseImportImpl
}

type StreamImportImpl struct {
	baseImportImpl
}

func (b *StreamImportImpl) AllowTracing() bool {
	return b.baseImportImpl.in.AllowTrace
}

func (b *StreamImportImpl) SetAllowTracing(tf bool) error {
	b.baseImportImpl.in.AllowTrace = tf
	return b.update()
}

func (b *baseImportImpl) update() error {
	if b.data == nil {
		// this is an unbounded export
		return nil
	}
	if err := b.data.update(); err != nil {
		return err
	}
	// update regenerated the claim, reload the reference
	if b.in.IsService() {
		e := b.data.getServiceImport(string(b.in.Subject))
		if e == nil {
			return errors.New("could not find service")
		}
		b.in = e.in
	} else if b.in.IsStream() {
		e := b.data.getStreamImport(string(b.in.Subject))
		if e == nil {
			return errors.New("could not find stream")
		}
		b.in = e.in
	} else {
		return errors.New("not implemented")
	}
	return nil
}

func (b *baseImportImpl) Name() string {
	return b.in.Name
}

func (b *baseImportImpl) SetName(n string) error {
	b.in.Name = n
	return b.update()
}

func (b *baseImportImpl) Subject() string {
	return string(b.in.Subject)
}

func (b *baseImportImpl) SetSubject(subject string) error {
	b.in.Subject = jwt.Subject(subject)
	return b.update()
}

func (b *baseImportImpl) Token() string {
	return b.in.Token
}

func (b *baseImportImpl) SetToken(s string) error {
	b.in.Token = s
	return b.update()
}

func (b *baseImportImpl) LocalSubject() string {
	return string(b.in.LocalSubject)
}

func (b *baseImportImpl) SetLocalSubject(subject string) error {
	b.in.LocalSubject = jwt.RenamingSubject(subject)
	return b.update()
}

func (b *baseImportImpl) Account() string {
	return b.in.Account
}

func (b *baseImportImpl) SetAccount(account string) error {
	k, err := KeyFrom(account, nkeys.PrefixByteAccount)
	if err != nil {
		return err
	}
	b.in.Account = k.Public
	return b.update()
}

func (b *baseImportImpl) Type() jwt.ExportType {
	return b.in.Type
}

func (b *baseImportImpl) IsShareConnectionInfo() bool {
	return b.in.Share
}

func (b *baseImportImpl) SetShareConnectionInfo(t bool) error {
	b.in.Share = t
	return b.update()
}
