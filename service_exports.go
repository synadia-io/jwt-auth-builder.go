package authb

import (
	"errors"

	"github.com/nats-io/jwt/v2"
)

type serviceExports struct {
	*AccountData
}

func (s *serviceExports) Get(subject string) ServiceExport {
	return s.getService(subject)
}

func (s *serviceExports) GetByName(name string) ServiceExport {
	for _, e := range s.Claim.Exports {
		if e.IsService() && e.Name == name {
			se := &ServiceExportImpl{}
			se.data = s.AccountData
			se.export = e
			return se
		}
	}
	return nil
}

func (s *serviceExports) List() []ServiceExport {
	return s.getServices()
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
	x := s.getService(subject)
	if x == nil {
		return nil, errors.New("could not find service")
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

	for _, e := range exports {
		ee, ok := e.(*ServiceExportImpl)
		if ok {
			buf = append(buf, ee.export)
		}
	}
	s.Claim.Exports = buf
	return s.update()
}

func (s *serviceExports) Delete(subject string) (bool, error) {
	return s.deleteExport(subject, true)
}
