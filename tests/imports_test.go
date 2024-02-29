package tests

import (
	"github.com/nats-io/nkeys"
	authb "github.com/synadia-io/jwt-auth-builder.go"
)

func (t *ProviderSuite) Test_ImportServiceRequiresName() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	ak := t.AccountKey()
	_, err = a.Imports().Services().Add("", ak.Public, "q.foo.>")
	t.Error(err)
}

func (t *ProviderSuite) Test_ImportServiceRequiresAccount() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	_, err = a.Imports().Services().Add("x", "", "q.foo.>")
	t.Error(err)
}

func (t *ProviderSuite) Test_ImportServiceRequiresSubject() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	ak := t.AccountKey()
	_, err = a.Imports().Services().Add("x", ak.Public, "")
	t.Error(err)
}

func (t *ProviderSuite) Test_ImportServiceOverlappingSubject() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	ak := t.AccountKey()
	_, err = a.Imports().Services().Add("x", ak.Public, "q")
	t.NoError(err)

	ak = t.AccountKey()
	_, err = a.Imports().Services().Add("y", ak.Public, "q")
	t.Error(err)
}

func (t *ProviderSuite) Test_ImportNameSubject() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	ak := t.AccountKey()
	im, err := a.Imports().Services().Add("x", ak.Public, "q")
	t.NoError(err)
	t.NotNil(im)
	t.Equal("x", im.Name())
	t.Equal(ak.Public, im.Account())
	t.Equal("q", im.Subject())

	akk := t.AccountKey()
	t.NoError(im.SetName("xx"))
	t.NoError(im.SetSubject("qq.>"))
	t.NoError(im.SetAccount(akk.Public))

	_, ok := a.Imports().Services().Get("q.>")
	t.False(ok)
	_, ok = a.Imports().Services().GetByName("q")
	t.False(ok)
	_, ok = a.Imports().Services().Get("qq.>")
	t.True(ok)
	_, ok = a.Imports().Services().GetByName("xx")
	t.True(ok)

	s, err := a.Imports().Streams().Add("s", ak.Public, "t.>")
	t.NoError(err)
	t.NotNil(s)
	t.Equal("s", s.Name())
	t.Equal(ak.Public, s.Account())
	t.Equal("t.>", s.Subject())

	t.NoError(s.SetName("ss"))
	t.NoError(s.SetSubject("tt.>"))
	t.NoError(s.SetAccount(akk.Public))

	_, ok = a.Imports().Streams().Get("t.>")
	t.False(ok)
	_, ok = a.Imports().Streams().GetByName("s")
	t.False(ok)
	_, ok = a.Imports().Streams().Get("tt.>")
	t.True(ok)
	_, ok = a.Imports().Streams().GetByName("ss")
	t.True(ok)
}

func (t *ProviderSuite) Test_ImportLocalSubject() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	ak := t.AccountKey()
	im, err := a.Imports().Services().Add("x", ak.Public, "q")
	t.NoError(err)
	t.NotNil(im)
	t.Equal("", im.LocalSubject())
	t.NoError(im.SetLocalSubject("myq"))
	t.Equal("myq", im.LocalSubject())

	s, err := a.Imports().Streams().Add("s", ak.Public, "t.>")
	t.NoError(err)
	t.NotNil(s)
	t.Equal("", s.LocalSubject())
	t.NoError(s.SetLocalSubject("ss.>"))
	t.Equal("ss.>", s.LocalSubject())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	a = t.GetAccount(auth, "O", "A")
	im, ok := a.Imports().Services().Get("q")
	t.True(ok)
	t.Equal("myq", im.LocalSubject())

	s, ok = a.Imports().Streams().Get("t.>")
	t.True(ok)
	t.Equal("ss.>", s.LocalSubject())
}

func (t *ProviderSuite) Test_ServiceImportCrud() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	ak := t.AccountKey()
	im, err := a.Imports().Services().Add("q", ak.Public, "q.>")
	t.NoError(err)
	t.NotNil(im)

	_, ok := a.Imports().Services().Get("q.>")
	t.True(ok)

	_, ok = a.Imports().Services().GetByName("q")
	t.True(ok)

	x, err := authb.NewServiceImport("x", ak.Public, "x.>")
	t.NoError(err)
	t.NotNil(x)

	y, err := authb.NewServiceImport("y", ak.Public, "y.>")
	t.NoError(err)
	t.NotNil(y)

	t.NoError(a.Imports().Services().Set(x, y))
	t.Len(a.Imports().Services().List(), 2)
	t.Equal("x.>", a.Imports().Services().List()[0].Subject())
	t.Equal("y.>", a.Imports().Services().List()[1].Subject())

	ok, err = a.Imports().Services().Delete("x.>")
	t.NoError(err)
	t.True(ok)

	ok, err = a.Imports().Services().Delete("x.>")
	t.NoError(err)
	t.False(ok)
}

func (t *ProviderSuite) Test_StreamImportCrud() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	ak := t.AccountKey()
	im, err := a.Imports().Streams().Add("q", ak.Public, "q.>")
	t.NoError(err)
	t.NotNil(im)

	_, ok := a.Imports().Streams().Get("q.>")
	t.True(ok)

	_, ok = a.Imports().Streams().GetByName("q")
	t.True(ok)

	x, err := authb.NewStreamImport("x", ak.Public, "x.>")
	t.NoError(err)
	t.NotNil(x)

	y, err := authb.NewStreamImport("y", ak.Public, "y.>")
	t.NoError(err)
	t.NotNil(y)

	_, err = a.Imports().Services().Add("q", ak.Public, "q.>")
	t.NoError(err)

	t.NoError(a.Imports().Streams().Set(x, y))
	t.Len(a.Imports().Streams().List(), 2)
	t.Equal("x.>", a.Imports().Streams().List()[0].Subject())
	t.Equal("y.>", a.Imports().Streams().List()[1].Subject())
	t.Len(a.Imports().Services().List(), 1)

	ok, err = a.Imports().Streams().Delete("x.>")
	t.NoError(err)
	t.True(ok)

	ok, err = a.Imports().Streams().Delete("x.>")
	t.NoError(err)
	t.False(ok)
}

func (t *ProviderSuite) Test_ServiceImportTraceable() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	akp := t.AccountKey()
	service, err := a.Imports().Services().Add("q", akp.Public, "q.>")
	t.NoError(err)
	t.False(service.IsShareConnectionInfo())
	t.NoError(service.SetShareConnectionInfo(true))
	t.True(service.IsShareConnectionInfo())
}

func (t *ProviderSuite) Test_StreamImportTraceable() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	akp := t.AccountKey()
	stream, err := a.Imports().Streams().Add("q", akp.Public, "q.>")
	t.NoError(err)
	t.False(stream.IsShareConnectionInfo())
	// FIXME: current JWT doesn't allow traceable outside of services
	t.Error(stream.SetShareConnectionInfo(true))
}

func (t *ProviderSuite) Test_NewServiceImportNameRequired() {
	akp := t.AccountKey()
	se, err := authb.NewServiceImport("", akp.Public, "subject")
	t.Error(err)
	t.Nil(se)
}

func (t *ProviderSuite) Test_NewServiceImportSubjectRequired() {
	akp := t.AccountKey()
	se, err := authb.NewServiceImport("n", akp.Public, "")
	t.Error(err)
	t.Nil(se)
}

func (t *ProviderSuite) Test_NewServiceImportAccountRequired() {
	se, err := authb.NewServiceImport("n", "", "subject")
	t.Error(err)
	t.Nil(se)
}

func (t *ProviderSuite) Test_NewStreamImportNameRequired() {
	akp := t.AccountKey()
	se, err := authb.NewStreamImport("", akp.Public, "subject")
	t.Error(err)
	t.Nil(se)
}

func (t *ProviderSuite) Test_NewStreamImportSubjectRequired() {
	akp := t.AccountKey()
	se, err := authb.NewStreamImport("n", akp.Public, "")
	t.Error(err)
	t.Nil(se)
}

func (t *ProviderSuite) Test_NewStreamImportAccountRequired() {
	se, err := authb.NewStreamImport("n", "", "subject")
	t.Error(err)
	t.Nil(se)
}

func (t *ProviderSuite) Test_GenerateStreamImport() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	stream, err := a.Exports().Streams().Add("q", "q.>")
	t.NoError(err)
	t.NotNil(stream)

	im, err := stream.GenerateImport()
	t.NoError(err)
	t.NotNil(im)
	t.Equal("q", im.Name())
	t.Equal("q.>", im.Subject())
	t.Equal(a.Subject(), im.Account())
}

func (t *ProviderSuite) Test_GenerateServiceImport() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.NotNil(service)

	im, err := service.GenerateImport()
	t.NoError(err)
	t.NotNil(im)
	t.Equal("q", im.Name())
	t.Equal("q.>", im.Subject())
	t.Equal(a.Subject(), im.Account())
}

func (t *ProviderSuite) Test_NewStreamImportToken() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	b := t.MaybeCreate(auth, "O", "Exporter")
	export, err := b.Exports().Streams().Add("s", "s.>")
	t.NoError(err)
	t.NotNil(export)
	t.NoError(export.SetTokenRequired(true))

	a := t.MaybeCreate(auth, "O", "A")
	si, err := export.GenerateImport()
	t.NoError(err)
	t.NotNil(si)

	token, err := export.GenerateActivation(a.Subject(), b.Subject())
	t.NoError(err)
	t.NotEmpty(token)
	t.NoError(si.SetToken(token))
}

func (t *ProviderSuite) Test_NewStreamImportSkToken() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	b := t.MaybeCreate(auth, "O", "Exporter")
	sk, err := b.ScopedSigningKeys().Add()
	t.NoError(err)
	t.NotEmpty(sk)

	export, err := b.Exports().Streams().Add("s", "s.>")
	t.NoError(err)
	t.NotNil(export)
	t.NoError(export.SetTokenRequired(true))

	a := t.MaybeCreate(auth, "O", "A")
	si, err := export.GenerateImport()
	t.NoError(err)
	t.NotNil(si)

	token, err := export.GenerateActivation(a.Subject(), sk)
	t.NoError(err)
	t.NotEmpty(token)
	t.NoError(si.SetToken(token))
}

func (t *ProviderSuite) Test_StreamImportAllowTracing() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NoError(err)

	ak, err := authb.KeyFor(nkeys.PrefixByteAccount)
	t.NoError(err)
	si, err := a.Imports().Streams().Add("X", ak.Public, "foo.>")
	t.NoError(err)

	t.False(si.AllowTracing())
	t.NoError(si.SetAllowTracing(true))
	t.True(si.AllowTracing())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	si, ok := a.Imports().Streams().Get("foo.>")
	t.True(ok)
	t.True(si.AllowTracing())
}

func (t *ProviderSuite) Test_NewServiceImportToken() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	b := t.MaybeCreate(auth, "O", "Exporter")
	export, err := b.Exports().Services().Add("s", "s.>")
	t.NoError(err)
	t.NotNil(export)
	t.NoError(export.SetTokenRequired(true))

	a := t.MaybeCreate(auth, "O", "A")
	si, err := export.GenerateImport()
	t.NoError(err)
	t.NotNil(si)

	token, err := export.GenerateActivation(a.Subject(), b.Subject())
	t.NoError(err)
	t.NotEmpty(token)
	t.NoError(si.SetToken(token))
}

func (t *ProviderSuite) Test_NewServiceImportSkToken() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	b := t.MaybeCreate(auth, "O", "Exporter")
	sk, err := b.ScopedSigningKeys().Add()
	t.NoError(err)
	t.NotEmpty(sk)

	export, err := b.Exports().Services().Add("s", "s.>")
	t.NoError(err)
	t.NotNil(export)
	t.NoError(export.SetTokenRequired(true))

	a := t.MaybeCreate(auth, "O", "A")
	si, err := export.GenerateImport()
	t.NoError(err)
	t.NotNil(si)

	token, err := export.GenerateActivation(a.Subject(), sk)
	t.NoError(err)
	t.NotEmpty(token)
	t.NoError(si.SetToken(token))
}
