package tests

import authb "github.com/synadia-io/jwt-auth-builder.go"

func (s *ProviderSuite) Test_ServiceExportCrud() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	a := s.MaybeCreate(auth, "O", "A")
	s.Len(a.Exports().Services().List(), 0)

	_, err = a.Exports().Services().Add("q", "q.>")
	s.NoError(err)
	s.Len(a.Exports().Services().List(), 1)

	service := a.Exports().Services().Get("q.>")
	s.NotNil(service)

	service = a.Exports().Services().GetByName("q")
	s.NotNil(service)

	x, err := authb.NewService("x", "x.>")
	s.NoError(err)

	y, err := authb.NewService("y", "y.>")
	s.NoError(err)

	s.NoError(a.Exports().Services().Set(x, y))
	s.Len(a.Exports().Services().List(), 2)
	s.Equal("x.>", a.Exports().Services().List()[0].Subject())
	s.Equal("y.>", a.Exports().Services().List()[1].Subject())

	ok, err := a.Exports().Services().Delete("x.>")
	s.NoError(err)
	s.True(ok)

	ok, err = a.Exports().Services().Delete("x.>")
	s.NoError(err)
	s.False(ok)
}

func (s *ProviderSuite) Test_StreamExportCrud() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	a := s.MaybeCreate(auth, "O", "A")
	s.Len(a.Exports().Streams().List(), 0)

	_, err = a.Exports().Streams().Add("q", "q.>")
	s.NoError(err)
	s.Len(a.Exports().Streams().List(), 1)

	stream := a.Exports().Streams().Get("q.>")
	s.NotNil(stream)

	stream = a.Exports().Streams().GetByName("q")
	s.NotNil(stream)

	x, err := authb.NewStream("x", "x.>")
	s.NoError(err)

	y, err := authb.NewStream("y", "y.>")
	s.NoError(err)

	s.NoError(a.Exports().Streams().Set(x, y))
	s.Len(a.Exports().Streams().List(), 2)
	s.Equal("x.>", a.Exports().Streams().List()[0].Subject())
	s.Equal("y.>", a.Exports().Streams().List()[1].Subject())

	ok, err := a.Exports().Streams().Delete("x.>")
	s.NoError(err)
	s.True(ok)

	ok, err = a.Exports().Streams().Delete("x.>")
	s.NoError(err)
	s.False(ok)
}

func (s *ProviderSuite) Test_ServiceTracing() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	a := s.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	s.NoError(err)

	s.Nil(service.Tracing())

	s.NoError(service.SetTracing(&authb.TracingConfiguration{
		SamplingRate: 100,
		Subject:      "tracing.q",
	}))

	tc := service.Tracing()
	s.NotNil(tc)
	s.Equal(authb.SamplingRate(100), tc.SamplingRate)
	s.Equal("tracing.q", tc.Subject)

	s.NoError(auth.Commit())
	s.NoError(auth.Reload())

	a = s.GetAccount(auth, "O", "A")
	service = a.Exports().Services().Get("q.>")

	tc = service.Tracing()
	s.NotNil(tc)
	s.Equal(authb.SamplingRate(100), tc.SamplingRate)
	s.Equal("tracing.q", tc.Subject)

	s.NoError(service.SetTracing(nil))
	s.Nil(service.Tracing())

	s.NoError(auth.Commit())
	s.NoError(auth.Reload())

	a = s.GetAccount(auth, "O", "A")
	service = a.Exports().Services().Get("q.>")
	tc = service.Tracing()
	s.Nil(tc)
}

func (s *ProviderSuite) Test_ServiceTracingRejectsBadOptions() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	a := s.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	s.NoError(err)

	s.Nil(service.Tracing())

	s.Error(service.SetTracing(&authb.TracingConfiguration{
		SamplingRate: 0,
		Subject:      "",
	}))

	s.Error(service.SetTracing(&authb.TracingConfiguration{
		SamplingRate: 1,
		Subject:      "",
	}))

	s.Error(service.SetTracing(&authb.TracingConfiguration{
		SamplingRate: 101,
		Subject:      "hello",
	}))
}
