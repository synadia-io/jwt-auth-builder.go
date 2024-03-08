package authb

import (
	"errors"

	"github.com/nats-io/jwt/v2"
)

type serviceExports struct {
	*AccountData
}

func (s *serviceExports) Get(subject string) (ServiceExport, error) {
	se := s.getServiceExport(subject)
	if se == nil {
		return nil, ErrNotFound
	}
	return se, nil
}

func (s *serviceExports) GetByName(name string) (ServiceExport, error) {
	for _, e := range s.Claim.Exports {
		if e.IsService() && e.Name == name {
			se := &ServiceExportImpl{}
			se.data = s.AccountData
			se.export = e
			return se, nil
		}
	}
	return nil, ErrNotFound
}

func (s *serviceExports) List() []ServiceExport {
	return s.getServiceExports()
}

func (s *serviceExports) AddWithConfig(e ServiceExport) error {
	if e == nil {
		return errors.New("invalid service export")
	}
	be, ok := e.(*ServiceExportImpl)
	if !ok {
		return errors.New("invalid service export")
	}
	if err := s.addExport(be.export); err != nil {
		return err
	}
	return s.update()
}

func (s *serviceExports) Add(name string, subject string) (ServiceExport, error) {
	err := s.newExport(name, subject, jwt.Service)
	if err != nil {
		return nil, err
	}
	// the pointer in the claim is changed by update, so we need to find it again
	x := s.getServiceExport(subject)
	if x == nil {
		return nil, errors.New("could not find service export")
	}
	if err := x.update(); err != nil {
		return nil, err
	}
	return x, nil
}

func (s *serviceExports) Set(exports ...ServiceExport) error {
	var buf []*jwt.Export
	// save existing streamExports
	for _, e := range s.Claim.Exports {
		if e.IsStream() {
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

func (s *serviceExports) Delete(subject string) (bool, error) {
	return s.deleteExport(subject, true)
}
