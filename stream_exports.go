package authb

import (
	"errors"

	"github.com/nats-io/jwt/v2"
)

type streamExports struct {
	*AccountData
}

func (s *streamExports) Get(subject string) StreamExport {
	return s.getStreamExport(subject)
}

func (s *streamExports) AddWithConfig(e StreamExport) error {
	if e == nil {
		return errors.New("invalid stream export")
	}
	be, ok := e.(*StreamExportImpl)
	if !ok {
		return errors.New("invalid stream export")
	}
	if err := s.addExport(be.export); err != nil {
		return err
	}
	return s.update()
}

func (s *streamExports) Add(name string, subject string) (StreamExport, error) {
	err := s.newExport(name, subject, jwt.Stream)
	if err != nil {
		return nil, err
	}
	// the pointer in the claim is changed by update, so we need to find it again
	x := s.getStreamExport(subject)
	if x == nil {
		return nil, errors.New("could not find stream")
	}
	return x, nil
}

func (s *streamExports) Set(exports ...StreamExport) error {
	var buf []*jwt.Export
	// save existing serviceExports
	for _, e := range s.Claim.Exports {
		if e.IsService() {
			buf = append(buf, e)
		}
	}
	s.Claim.Exports = buf
	for _, e := range exports {
		if err := s.AddWithConfig(e); err != nil {
			return err
		}
	}
	return s.update()
}

func (s *streamExports) Delete(subject string) (bool, error) {
	return s.deleteExport(subject, false)
}

func (s *streamExports) GetByName(name string) StreamExport {
	for _, e := range s.Claim.Exports {
		if e.IsStream() && e.Name == name {
			se := &StreamExportImpl{}
			se.data = s.AccountData
			se.export = e
			return se
		}
	}
	return nil
}

func (s *streamExports) List() []StreamExport {
	return s.getStreamExports()
}
