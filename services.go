package authb

import (
	"errors"

	"github.com/nats-io/jwt/v2"
)

type serviceExports struct {
	*AccountData
}

func (a *serviceExports) Get(subject string) ServiceExport {
	return a.getService(subject)
}

func (a *serviceExports) GetByName(name string) ServiceExport {
	for _, e := range a.Claim.Exports {
		if e.IsService() && e.Name == name {
			se := &ServiceExportImpl{}
			se.data = a.AccountData
			se.export = e
			return se
		}
	}
	return nil
}

func (a *serviceExports) List() []ServiceExport {
	return a.getServices()
}

func (a *serviceExports) AddWithConfig(e ServiceExport) error {
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

func (a *serviceExports) Add(name string, subject string) (ServiceExport, error) {
	err := a.newExport(name, subject, jwt.Service)
	if err != nil {
		return nil, err
	}
	// the pointer in the claim is changed by update, so we need to find it again
	x := a.getService(subject)
	if x == nil {
		return nil, errors.New("could not find service")
	}
	return x, nil
}

func (a *serviceExports) Set(exports ...ServiceExport) error {
	var buf []*jwt.Export
	// save existing streamExports
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

func (a *serviceExports) Delete(subject string) (bool, error) {
	return a.deleteExport(subject, true)
}
