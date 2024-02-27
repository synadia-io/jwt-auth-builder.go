package authb

import (
	"errors"
	"fmt"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

type ServiceExportImpl struct {
	baseExportImpl
}

func NewServiceExport(name string, subject string) (ServiceExport, error) {
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

func (b *ServiceExportImpl) GetLatencyOptions() *LatencyOpts {
	lat := b.export.Latency
	if lat == nil {
		return nil
	}
	return &LatencyOpts{
		SamplingRate: SamplingRate(lat.Sampling),
		Subject:      string(lat.Results),
	}
}

func (b *ServiceExportImpl) SetLatencyOptions(t *LatencyOpts) error {
	if t == nil {
		b.export.Latency = nil
	} else {
		b.export.Latency = &jwt.ServiceLatency{
			Sampling: jwt.SamplingRate(t.SamplingRate),
			Results:  jwt.Subject(t.Subject),
		}
	}
	return b.update()
}

func (b *ServiceExportImpl) GenerateImport() (ServiceImport, error) {
	return NewServiceImport(b.export.Name, b.data.Claim.Subject, string(b.export.Subject))
}

func (b *ServiceExportImpl) AllowTracing() bool {
	return b.export.AllowTrace
}

func (b *ServiceExportImpl) SetAllowTracing(tf bool) error {
	b.export.AllowTrace = tf
	return b.update()
}

type StreamExportImpl struct {
	baseExportImpl
}

func (b *StreamExportImpl) GenerateImport() (StreamImport, error) {
	return NewStreamImport(b.export.Name, b.data.Claim.Subject, string(b.export.Subject))
}

func NewStreamExport(name string, subject string) (StreamExport, error) {
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	if subject == "" {
		return nil, errors.New("subject cannot be empty")
	}

	return &StreamExportImpl{
		baseExportImpl{
			data:   nil,
			export: &jwt.Export{Name: name, Subject: jwt.Subject(subject), Type: jwt.Stream},
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
		e := b.data.getServiceExport(string(b.export.Subject))
		if e == nil {
			return errors.New("could not find service")
		}
		b.export = e.export
	} else if b.export.IsStream() {
		e := b.data.getStreamExport(string(b.export.Subject))
		if e == nil {
			return errors.New("could not find stream")
		}
		b.export = e.export
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

func (b *baseExportImpl) Description() string {
	return b.export.Description
}

func (b *baseExportImpl) SetDescription(s string) error {
	b.export.Description = s
	return b.update()
}

func (b *baseExportImpl) InfoURL() string {
	return b.export.InfoURL
}

func (b *baseExportImpl) SetInfoURL(u string) error {
	b.export.InfoURL = u
	return b.update()
}

func (b *baseExportImpl) AccountTokenPosition() uint {
	return b.export.AccountTokenPosition
}

func (b *baseExportImpl) SetAccountTokenPosition(n uint) error {
	b.export.AccountTokenPosition = n
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

func (b *baseExportImpl) IsAdvertised() bool {
	return b.export.Advertise
}

func (b *baseExportImpl) SetAdvertised(tf bool) error {
	b.export.Advertise = tf
	return b.update()
}

func (b *baseExportImpl) GenerateActivation(account string, issuer string) (string, error) {
	if !b.TokenRequired() {
		return "", fmt.Errorf("export is public and doesn't require an activation")
	}
	key, err := KeyFrom(account, nkeys.PrefixByteAccount)
	if err != nil {
		return "", err
	}
	ac := jwt.NewActivationClaims(key.Public)
	ac.ImportSubject = b.export.Subject
	ac.ImportType = b.export.Type

	k, signingKey, err := b.data.getKey(issuer)
	if err != nil {
		return "", err
	}
	if signingKey {
		ac.IssuerAccount = b.data.Claim.Subject
	}
	return ac.Encode(k.Pair)
}
