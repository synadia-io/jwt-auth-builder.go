package authb

import (
	"errors"
	"github.com/nats-io/jwt/v2"
)

type streamImports struct {
	*AccountData
}

func (s *streamImports) Get(subject string) StreamImport {
	return s.getStreamImport(subject)
}

func (s *streamImports) AddWithConfig(i StreamImport) error {
	if i == nil {
		return errors.New("invalid stream import")
	}
	be, ok := i.(*StreamImportImpl)
	if !ok {
		return errors.New("invalid stream import")
	}
	if err := s.addImport(be.in); err != nil {
		return err
	}
	return s.update()
}

func (s *streamImports) Add(name string, account string, subject string) (StreamImport, error) {
	if err := s.newImport(name, account, subject, jwt.Stream); err != nil {
		return nil, err
	}
	x := s.getStreamImport(subject)
	if x == nil {
		return nil, errors.New("could not find stream")
	}
	return x, nil
}

func (s *streamImports) Set(imports ...StreamImport) error {
	var buf []*jwt.Import
	for _, e := range s.Claim.Imports {
		if e.IsService() {
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

func (s *streamImports) Delete(subject string) (bool, error) {
	return s.deleteImport(subject, false)
}

func (a *AccountData) GetByName(name string) StreamImport {
	for _, e := range a.Claim.Imports {
		if e.IsStream() && e.Name == name {
			se := &StreamImportImpl{}
			se.data = a
			se.in = e
			return se
		}
	}
	return nil
}

func (s *streamImports) List() []StreamImport {
	return s.getStreamImports()
}
