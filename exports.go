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

func (a *AccountData) getStreams() []StreamExport {
	var buf []StreamExport
	for _, e := range a.Claim.Exports {
		if e.IsStream() {
			se := &StreamExportImpl{}
			se.data = a
			se.export = e
			buf = append(buf, se)
		}
	}
	return buf
}

func (a *AccountData) GetStream(subject string) StreamExport {
	for _, e := range a.Claim.Exports {
		if e.IsStream() && string(e.Subject) == subject {
			se := &StreamExportImpl{}
			se.data = a
			se.export = e
			return se
		}
	}
	return nil
}

func (a *AccountData) GetService(subject string) ServiceExport {
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

func (a *AccountData) GetServiceByName(name string) ServiceExport {
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

func (a *AccountData) GetStreamByName(name string) StreamExport {
	for _, e := range a.Claim.Exports {
		if e.IsStream() && e.Name == name {
			se := &StreamExportImpl{}
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

func (a *AccountData) Streams() []StreamExport {
	return a.getStreams()
}

func (a *AccountData) addExport(export *jwt.Export) error {
	if export == nil {
		return errors.New("invalid export")
	}
	if export.Name == "" {
		return errors.New("export name is not specified")
	}
	if export.Type == jwt.Unknown {
		return errors.New("export type is not specified")
	}
	if export.Subject == "" {
		return errors.New("export subject is not specified")
	}

	if export.IsService() {
		if a.GetService(string(export.Subject)) != nil {
			return errors.New("service export already exists")
		}
	} else {
		if a.GetStream(string(export.Subject)) != nil {
			return errors.New("stream export already exists")
		}
	}
	a.Claim.Exports = append(a.Claim.Exports, export)
	return nil
}

func (a *AccountData) newExport(name string, subject string, kind jwt.ExportType) error {
	export := &jwt.Export{
		Name:    name,
		Subject: jwt.Subject(subject),
		Type:    kind,
	}
	return a.addExport(export)
}

func (a *AccountData) AddServiceWithConfig(e ServiceExport) error {
	if e == nil {
		return errors.New("invalid service export")
	}
	be, ok := e.(*ServiceExportImpl)
	if !ok {
		return errors.New("invalid service export")
	}
	if err := a.addExport(be.export); err != nil {
		return err
	}
	return a.update()
}

func (a *AccountData) AddStreamWithConfig(e StreamExport) error {
	if e == nil {
		return errors.New("invalid stream export")
	}
	be, ok := e.(*StreamExportImpl)
	if !ok {
		return errors.New("invalid stream export")
	}
	if err := a.addExport(be.export); err != nil {
		return err
	}
	return a.update()
}

func (a *AccountData) AddService(name string, subject string) (ServiceExport, error) {
	err := a.newExport(name, subject, jwt.Service)
	if err != nil {
		return nil, err
	}
	// the pointer in the claim is changed by update, so we need to find it again
	x := a.GetService(subject)
	if x == nil {
		return nil, errors.New("could not find service")
	}
	return x, nil
}

func (a *AccountData) AddStream(name string, subject string) (StreamExport, error) {
	err := a.newExport(name, subject, jwt.Stream)
	if err != nil {
		return nil, err
	}
	// the pointer in the claim is changed by update, so we need to find it again
	x := a.GetStream(subject)
	if x == nil {
		return nil, errors.New("could not find stream")
	}
	return x, nil
}

func (a *AccountData) SetServices(exports ...ServiceExport) error {
	var buf []*jwt.Export
	// save existing streams
	for _, e := range a.Claim.Exports {
		if e.IsStream() {
			buf = append(buf, e)
		}
	}

	for _, e := range exports {
		ee, ok := e.(*ServiceExportImpl)
		if ok {
			buf = append(buf, ee.export)
		}
	}
	a.Claim.Exports = buf
	return a.update()
}

func (a *AccountData) SetStreams(exports ...StreamExport) error {
	var buf []*jwt.Export
	// save existing services
	for _, e := range a.Claim.Exports {
		if e.IsService() {
			buf = append(buf, e)
		}
	}
	for _, e := range exports {
		ee, ok := e.(*StreamExportImpl)
		if ok {
			buf = append(buf, ee.export)
		}
	}
	a.Claim.Exports = buf
	return a.update()
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
		e := b.data.GetService(string(b.export.Subject))
		if e == nil {
			return errors.New("could not find service")
		}
		b.export = e.(*ServiceExportImpl).export
	} else if b.export.IsStream() {
		e := b.data.GetStream(string(b.export.Subject))
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

type ServiceExportImpl struct {
	baseExportImpl
}

type StreamExportImpl struct {
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
