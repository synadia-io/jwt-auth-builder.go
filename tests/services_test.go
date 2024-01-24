package tests

import authb "github.com/synadia-io/jwt-auth-builder.go"

func (t *ProviderSuite) Test_ServiceExportCrud() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	t.Len(a.Exports().Services().List(), 0)

	_, err = a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.Len(a.Exports().Services().List(), 1)

	service := a.Exports().Services().Get("q.>")
	t.NotNil(service)

	service = a.Exports().Services().GetByName("q")
	t.NotNil(service)

	x, err := authb.NewService("x", "x.>")
	t.NoError(err)

	y, err := authb.NewService("y", "y.>")
	t.NoError(err)

	t.NoError(a.Exports().Services().Set(x, y))
	t.Len(a.Exports().Services().List(), 2)
	t.Equal("x.>", a.Exports().Services().List()[0].Subject())
	t.Equal("y.>", a.Exports().Services().List()[1].Subject())

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

	stream := a.Exports().Streams().Get("q.>")
	t.NotNil(stream)

	stream = a.Exports().Streams().GetByName("q")
	t.NotNil(stream)

	x, err := authb.NewStream("x", "x.>")
	t.NoError(err)

	y, err := authb.NewStream("y", "y.>")
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

func (t *ProviderSuite) Test_ServiceTracing() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)

	t.Nil(service.Tracing())

	t.NoError(service.SetTracing(&authb.TracingConfiguration{
		SamplingRate: 100,
		Subject:      "tracing.q",
	}))

	tc := service.Tracing()
	t.NotNil(tc)
	t.Equal(authb.SamplingRate(100), tc.SamplingRate)
	t.Equal("tracing.q", tc.Subject)

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	a = t.GetAccount(auth, "O", "A")
	service = a.Exports().Services().Get("q.>")

	tc = service.Tracing()
	t.NotNil(tc)
	t.Equal(authb.SamplingRate(100), tc.SamplingRate)
	t.Equal("tracing.q", tc.Subject)

	t.NoError(service.SetTracing(nil))
	t.Nil(service.Tracing())

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	a = t.GetAccount(auth, "O", "A")
	service = a.Exports().Services().Get("q.>")
	tc = service.Tracing()
	t.Nil(tc)
}

func (t *ProviderSuite) Test_ServiceTracingRejectsBadOptions() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)

	t.Nil(service.Tracing())

	t.Error(service.SetTracing(&authb.TracingConfiguration{
		SamplingRate: 0,
		Subject:      "",
	}))

	t.Error(service.SetTracing(&authb.TracingConfiguration{
		SamplingRate: 1,
		Subject:      "",
	}))

	t.Error(service.SetTracing(&authb.TracingConfiguration{
		SamplingRate: 101,
		Subject:      "hello",
	}))
}
