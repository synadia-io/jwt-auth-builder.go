package authb

import (
	"errors"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func (a *AccountData) getServices() []ServiceExport {
	var buf []ServiceExport
	for _, e := range a.Claim.Exports {
		if e.IsService() {
			se := &ServiceExportImpl{}
			se.data = a
			se.export = e
			buf = append(buf, se)
		}
	}
	return buf
}

func (a *AccountData) FindServiceBySubject(subject string) ServiceExport {
	for _, e := range a.Claim.Exports {
		if e.IsService() && string(e.Subject) == subject {
			se := &ServiceExportImpl{}
			se.data = a
			se.export = e
			return se
		}
	}
	return nil
}

func (a *AccountData) FindServiceByName(name string) ServiceExport {
	for _, e := range a.Claim.Exports {
		if e.IsService() && e.Name == name {
			se := &ServiceExportImpl{}
			se.data = a
			se.export = e
			return se
		}
	}
	return nil
}

func (a *AccountData) Services() []ServiceExport {
	return a.getServices()
}

func (a *AccountData) AddService(e ServiceExport) error {
	be, ok := e.(*ServiceExportImpl)
	if !ok {
		return errors.New("invalid service export")
	}
	a.Claim.Exports = append(a.Claim.Exports, be.export)
	if err := a.update(); err != nil {
		return err
	}
	return nil
}

func (a *AccountData) NewService(name string, subject string) (ServiceExport, error) {
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	if subject == "" {
		return nil, errors.New("subject cannot be empty")
	}

	export := &jwt.Export{
		Name:    name,
		Subject: jwt.Subject(subject),
		Type:    jwt.Service,
	}

	a.Claim.Exports.Add(export)
	if err := a.update(); err != nil {
		return nil, err
	}
	// the pointer in the claim is changed by update, so we need to find it again
	x := a.FindServiceBySubject(string(export.Subject))
	if x == nil {
		return nil, errors.New("could not find service")
	}
	return x, nil
}

func (a *AccountData) SetServices(exports ...ServiceExport) error {
	var buf []*jwt.Export
	for _, e := range a.Claim.Exports {
		if e.IsStream() {
			buf = append(buf, e)
		}
	}
	for _, e := range exports {
		ee := *e.(*baseExport).export
		buf = append(buf, &ee)
	}
	a.Claim.Exports = buf
	return a.update()
}

type baseExport struct {
	data   *AccountData
	export *jwt.Export
}

func (b *baseExport) update() error {
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
		e := b.data.FindServiceBySubject(string(b.export.Subject))
		if e == nil {
			return errors.New("could not find service")
		}
		b.export = e.(*ServiceExportImpl).export
	} else {
		return errors.New("not implemented")
	}
	return nil
}

func (b *baseExport) Name() string {
	return b.export.Name
}

func (b *baseExport) SetName(n string) error {
	b.export.Name = n
	return b.update()
}

func (b *baseExport) Subject() string {
	return string(b.export.Subject)
}

func (b *baseExport) SetSubject(subject string) error {
	b.export.Subject = jwt.Subject(subject)
	return b.update()
}

func (b *baseExport) TokenRequired() bool {
	return b.export.TokenReq
}
func (b *baseExport) SetTokenRequired(tf bool) error {
	b.export.TokenReq = tf
	return b.update()
}

func (b *baseExport) getRevocations() jwt.RevocationList {
	if b.export.Revocations == nil {
		b.export.Revocations = jwt.RevocationList{}
	}
	return b.export.Revocations
}

func (b *baseExport) getRevocationPrefix() nkeys.PrefixByte {
	return nkeys.PrefixByteAccount
}

func (b *baseExport) Revocations() Revocations {
	return &revocations{data: b}
}

type ServiceExportImpl struct {
	baseExport
}

func NewService(name string, subject string) (ServiceExport, error) {
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	if subject == "" {
		return nil, errors.New("subject cannot be empty")
	}

	return &ServiceExportImpl{
		baseExport{
			data:   nil,
			export: &jwt.Export{Name: name, Subject: jwt.Subject(subject), Type: jwt.Service},
		},
	}, nil
}
