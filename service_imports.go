package authb

import (
	"errors"

	"github.com/nats-io/jwt/v2"
)

type serviceImports struct {
	*AccountData
}

func (s *serviceImports) Add(name string, account string, subject string) (ServiceImport, error) {
	if err := s.newImport(name, account, subject, jwt.Service); err != nil {
		return nil, err
	}
	i := s.getServiceImport(subject)
	if i == nil {
		return nil, errors.New("could not find service import")
	}

	if err := i.update(); err != nil {
		return nil, err
	}
	return i, nil
}

func (s *serviceImports) AddWithConfig(i ServiceImport) error {
	if i == nil {
		return errors.New("invalid stream export")
	}
	be, ok := i.(*ServiceImportImpl)
	if !ok {
		return errors.New("invalid service import")
	}
	if err := s.addImport(be.in); err != nil {
		return err
	}
	return s.update()
}

func (s *serviceImports) Get(subject string) (ServiceImport, error) {
	si := s.getServiceImport(subject)
	if si != nil {
		return si, nil
	}
	return nil, ErrNotFound
}

func (s *serviceImports) GetByName(name string) (ServiceImport, error) {
	for _, e := range s.Claim.Imports {
		if e.IsService() && e.Name == name {
			se := &ServiceImportImpl{}
			se.data = s.AccountData
			se.in = e
			return se, nil
		}
	}
	return nil, ErrNotFound
}

func (s *serviceImports) Delete(subject string) (bool, error) {
	return s.deleteImport(subject, true)
}

func (s *serviceImports) List() []ServiceImport {
	return s.getServiceImports()
}

func (s *serviceImports) Set(imports ...ServiceImport) error {
	var buf []*jwt.Import
	for _, e := range s.Claim.Imports {
		if e.IsStream() {
			buf = append(buf, e)
		}
	}
	s.Claim.Imports = buf
	for _, e := range imports {
		if err := s.AddWithConfig(e); err != nil {
			return err
		}
	}
	return s.update()
}
