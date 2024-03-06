package tests

import authb "github.com/synadia-io/jwt-auth-builder.go"

func (t *ProviderSuite) Test_ServiceRequiresName() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	_, err = a.Exports().Services().Add("", "q.foo.>")
	t.Error(err)
}

func (t *ProviderSuite) Test_StreamRequiresName() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	_, err = a.Exports().Streams().Add("", "t.>")
	t.Error(err)
}

func (t *ProviderSuite) Test_ServiceRequiresSubject() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	_, err = a.Exports().Services().Add("name", "")
	t.Error(err)
}

func (t *ProviderSuite) Test_StreamRequiresSubject() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	_, err = a.Exports().Streams().Add("name", "")
	t.Error(err)
}

func (t *ProviderSuite) Test_ServiceExportNoDuplicates() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)
	_, err = a.Exports().Services().Add("q", "q")
	t.NoError(err)
	_, err = a.Exports().Services().Add("qq", "q")
	t.Error(err)
}

func (t *ProviderSuite) Test_ExportTokenRequired() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.NoError(service.SetTokenRequired(true))
	t.Equal(true, service.TokenRequired())

	stream, err := a.Exports().Streams().Add("s", "t.>")
	t.NoError(err)
	t.NoError(stream.SetTokenRequired(true))
	t.Equal(true, stream.TokenRequired())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	a = t.GetAccount(auth, "O", "A")
	service, err = a.Exports().Services().Get("q.>")
	t.NoError(err)
	t.True(service.TokenRequired())

	stream, err = a.Exports().Streams().Get("t.>")
	t.NoError(err)
	t.True(stream.TokenRequired())
}

func (t *ProviderSuite) Test_ExportNameSubject() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.Equal("q", service.Name())
	t.Equal("q.>", service.Subject())

	t.NoError(service.SetName("qq"))
	t.NoError(service.SetSubject("qq.>"))

	_, err = a.Exports().Services().Get("q.>")
	t.ErrorIs(err, authb.ErrNotFound)
	_, err = a.Exports().Services().GetByName("q")
	t.ErrorIs(err, authb.ErrNotFound)
	_, err = a.Exports().Services().Get("qq.>")
	t.NoError(err)
	_, err = a.Exports().Services().GetByName("qq")
	t.NoError(err)

	stream, err := a.Exports().Streams().Add("s", "t.>")
	t.NoError(err)
	t.Equal("s", stream.Name())
	t.Equal("t.>", stream.Subject())

	t.NoError(stream.SetName("ss"))
	t.NoError(stream.SetSubject("st.>"))

	_, err = a.Exports().Streams().Get("t.>")
	t.ErrorIs(err, authb.ErrNotFound)
	_, err = a.Exports().Streams().GetByName("s")
	t.ErrorIs(err, authb.ErrNotFound)
	_, err = a.Exports().Streams().Get("st.>")
	t.NoError(err)
	_, err = a.Exports().Streams().GetByName("ss")
	t.NoError(err)
}

func (t *ProviderSuite) Test_ExportDescription() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.NoError(service.SetDescription("desc"))
	t.Equal("desc", service.Description())

	stream, err := a.Exports().Streams().Add("s", "t.>")
	t.NoError(err)
	t.NoError(stream.SetDescription("desc"))
	t.Equal("desc", stream.Description())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	a = t.GetAccount(auth, "O", "A")
	service, err = a.Exports().Services().Get("q.>")
	t.NoError(err)
	t.Equal("desc", service.Description())

	stream, err = a.Exports().Streams().Get("t.>")
	t.NoError(err)
	t.Equal("desc", stream.Description())
}

func (t *ProviderSuite) Test_ExportInfoURL() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.NoError(service.SetInfoURL("https://service.com"))
	t.Equal("https://service.com", service.InfoURL())

	stream, err := a.Exports().Streams().Add("s", "t.>")
	t.NoError(err)
	t.NoError(stream.SetInfoURL("https://stream.com"))
	t.Equal("https://stream.com", stream.InfoURL())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	a = t.GetAccount(auth, "O", "A")
	service, err = a.Exports().Services().Get("q.>")
	t.NoError(err)
	t.Equal("https://service.com", service.InfoURL())

	stream, err = a.Exports().Streams().Get("t.>")
	t.NoError(err)
	t.Equal("https://stream.com", stream.InfoURL())
}

func (t *ProviderSuite) Test_ExportAccountTokenPosition() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.*")
	t.NoError(err)
	t.NoError(service.SetAccountTokenPosition(2))
	t.Equal(uint(2), service.AccountTokenPosition())

	stream, err := a.Exports().Streams().Add("s", "t.*")
	t.NoError(err)
	t.NoError(stream.SetAccountTokenPosition(2))
	t.Equal(uint(2), stream.AccountTokenPosition())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	a = t.GetAccount(auth, "O", "A")
	service, err = a.Exports().Services().Get("q.*")
	t.NoError(err)
	t.Equal(uint(2), service.AccountTokenPosition())

	stream, err = a.Exports().Streams().Get("t.*")
	t.NoError(err)
	t.Equal(uint(2), stream.AccountTokenPosition())
}

func (t *ProviderSuite) Test_ExportAccountTokenPositionRequiresWildcards() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)
	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.a")
	t.NoError(err)
	t.Error(service.SetAccountTokenPosition(2))

	stream, err := a.Exports().Streams().Add("s", "t.a")
	t.NoError(err)
	t.Error(stream.SetAccountTokenPosition(2))
}

func (t *ProviderSuite) Test_ServiceExportCrud() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.Len(a.Exports().Services().List(), 0)

	_, err = a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.Len(a.Exports().Services().List(), 1)

	_, err = a.Exports().Services().Get("q.>")
	t.NoError(err)

	_, err = a.Exports().Services().GetByName("q")
	t.NoError(err)

	x, err := authb.NewServiceExport("x", "x.>")
	t.NoError(err)
	t.NotNil(x)

	y, err := authb.NewServiceExport("y", "y.>")
	t.NoError(err)
	t.NotNil(y)

	_, err = a.Exports().Streams().Add("s", "s.>")
	t.NoError(err)

	t.NoError(a.Exports().Services().Set(x, y))
	t.Len(a.Exports().Services().List(), 2)
	t.Equal("x.>", a.Exports().Services().List()[0].Subject())
	t.Equal("y.>", a.Exports().Services().List()[1].Subject())
	t.Len(a.Exports().Streams().List(), 1)

	ok, err := a.Exports().Services().Delete("x.>")
	t.NoError(err)
	t.True(ok)

	ok, err = a.Exports().Services().Delete("x.>")
	t.NoError(err)
	t.False(ok)
}

func (t *ProviderSuite) Test_StreamExportCrud() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.Len(a.Exports().Streams().List(), 0)

	_, err = a.Exports().Streams().Add("q", "q.>")
	t.NoError(err)
	t.Len(a.Exports().Streams().List(), 1)

	_, err = a.Exports().Streams().Get("q.>")
	t.NoError(err)

	_, err = a.Exports().Streams().GetByName("q")
	t.NoError(err)

	x, err := authb.NewStreamExport("x", "x.>")
	t.NoError(err)

	y, err := authb.NewStreamExport("y", "y.>")
	t.NoError(err)

	t.NoError(a.Exports().Streams().Set(x, y))
	t.Len(a.Exports().Streams().List(), 2)
	t.Equal("x.>", a.Exports().Streams().List()[0].Subject())
	t.Equal("y.>", a.Exports().Streams().List()[1].Subject())

	ok, err := a.Exports().Streams().Delete("x.>")
	t.NoError(err)
	t.True(ok)

	ok, err = a.Exports().Streams().Delete("x.>")
	t.NoError(err)
	t.False(ok)
}

func (t *ProviderSuite) Test_ServiceExportTracing() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)

	t.Nil(service.GetLatencyOptions())

	t.NoError(service.SetLatencyOptions(&authb.LatencyOpts{
		SamplingRate: 100,
		Subject:      "tracing.q",
	}))

	tc := service.GetLatencyOptions()
	t.NotNil(tc)
	t.Equal(authb.SamplingRate(100), tc.SamplingRate)
	t.Equal("tracing.q", tc.Subject)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	a = t.GetAccount(auth, "O", "A")
	service, err = a.Exports().Services().Get("q.>")
	t.NoError(err)

	tc = service.GetLatencyOptions()
	t.NotNil(tc)
	t.Equal(authb.SamplingRate(100), tc.SamplingRate)
	t.Equal("tracing.q", tc.Subject)

	t.NoError(service.SetLatencyOptions(nil))
	t.Nil(service.GetLatencyOptions())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	a = t.GetAccount(auth, "O", "A")
	service, _ = a.Exports().Services().Get("q.>")
	tc = service.GetLatencyOptions()
	t.Nil(tc)
}

func (t *ProviderSuite) Test_ServiceExportTracingRejectsBadOptions() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)

	t.Nil(service.GetLatencyOptions())

	t.Error(service.SetLatencyOptions(&authb.LatencyOpts{
		SamplingRate: 0,
		Subject:      "",
	}))

	t.Error(service.SetLatencyOptions(&authb.LatencyOpts{
		SamplingRate: 1,
		Subject:      "",
	}))

	t.Error(service.SetLatencyOptions(&authb.LatencyOpts{
		SamplingRate: 101,
		Subject:      "hello",
	}))
}

func (t *ProviderSuite) Test_NewServiceExportNameRequired() {
	se, err := authb.NewServiceExport("", "subject")
	t.Error(err)
	t.Nil(se)
}

func (t *ProviderSuite) Test_NewServiceExportSubjectRequired() {
	se, err := authb.NewServiceExport("n", "")
	t.Error(err)
	t.Nil(se)
}

func (t *ProviderSuite) Test_ServiceAllowTracing() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.False(service.AllowTracing())
	t.NoError(service.SetAllowTracing(true))
	t.True(service.AllowTracing())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	se, err := a.Exports().Services().Get("q.>")
	t.NoError(err)
	t.True(se.AllowTracing())
}

func (t *ProviderSuite) Test_NewStreamExportNameRequired() {
	se, err := authb.NewStreamExport("", "subject")
	t.Error(err)
	t.Nil(se)
}

func (t *ProviderSuite) Test_NewStreamExportSubjectRequired() {
	se, err := authb.NewStreamExport("n", "")
	t.Error(err)
	t.Nil(se)
}

func (t *ProviderSuite) Test_ServiceExportAdvertised() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.False(service.IsAdvertised())
	t.NoError(service.SetAdvertised(true))
	t.True(service.IsAdvertised())
}

func (t *ProviderSuite) Test_StreamExportAdvertised() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	stream, err := a.Exports().Streams().Add("q", "q.>")
	t.NoError(err)
	t.False(stream.IsAdvertised())
	t.NoError(stream.SetAdvertised(true))
	t.True(stream.IsAdvertised())
}
