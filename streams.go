package authb

import (
	"errors"

	"github.com/nats-io/jwt/v2"
)

type streams struct {
	*AccountData
}

func (s *streams) GetStream(subject string) StreamExport {
	return s.getStream(subject)
}

func (s *streams) AddStreamWithConfig(e StreamExport) error {
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

func (s *streams) AddStream(name string, subject string) (StreamExport, error) {
	err := s.newExport(name, subject, jwt.Stream)
	if err != nil {
		return nil, err
	}
	// the pointer in the claim is changed by update, so we need to find it again
	x := s.getStream(subject)
	if x == nil {
		return nil, errors.New("could not find stream")
	}
	return x, nil
}

func (s *streams) SetStreams(exports ...StreamExport) error {
	var buf []*jwt.Export
	// save existing services
	for _, e := range s.Claim.Exports {
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
	s.Claim.Exports = buf
	return s.update()
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

func (a *AccountData) ListStreams() []StreamExport {
	return a.getStreams()
}
