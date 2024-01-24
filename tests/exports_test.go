package tests

import authb "github.com/synadia-io/jwt-auth-builder.go"

func (s *ProviderSuite) Test_ServiceRequiresName() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	operators := auth.Operators()
	s.Empty(operators.List())

	a := s.MaybeCreate(auth, "O", "A")
	s.NotNil(a)

	_, err = a.Exports().Services().Add("", "q.foo.>")
	s.Error(err)
}

func (s *ProviderSuite) Test_StreamRequiresName() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	operators := auth.Operators()
	s.Empty(operators.List())

	a := s.MaybeCreate(auth, "O", "A")
	s.NotNil(a)

	_, err = a.Exports().Streams().Add("", "s.>")
	s.Error(err)
}

func (s *ProviderSuite) Test_ServiceRequiresSubject() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	operators := auth.Operators()
	s.Empty(operators.List())

	o, err := operators.Add("O")
	s.NoError(err)
	s.NotNil(o)

	a, err := o.Accounts().Add("A")
	s.NoError(err)
	s.NotNil(a)

	_, err = a.Exports().Services().Add("name", "")
	s.Error(err)
}

func (s *ProviderSuite) Test_StreamRequiresSubject() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	operators := auth.Operators()
	s.Empty(operators.List())

	o, err := operators.Add("O")
	s.NoError(err)
	s.NotNil(o)

	a, err := o.Accounts().Add("A")
	s.NoError(err)
	s.NotNil(a)

	_, err = a.Exports().Streams().Add("name", "")
	s.Error(err)
}

func (s *ProviderSuite) Test_ExportTokenRequired() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)
	a := s.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	s.NoError(err)
	s.NoError(service.SetTokenRequired(true))
	s.Equal(true, service.TokenRequired())

	stream, err := a.Exports().Streams().Add("s", "s.>")
	s.NoError(err)
	s.NoError(stream.SetTokenRequired(true))
	s.Equal(true, stream.TokenRequired())

	s.NoError(auth.Commit())
	s.NoError(auth.Reload())

	a = s.GetAccount(auth, "O", "A")
	service = a.Exports().Services().Get("q.>")
	s.NotNil(service)
	s.True(service.TokenRequired())

	stream = a.Exports().Streams().Get("s.>")
	s.NotNil(stream)
	s.True(stream.TokenRequired())
}

func (s *ProviderSuite) Test_ExportNameSubject() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)
	a := s.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	s.NoError(err)
	s.Equal("q", service.Name())
	s.Equal("q.>", service.Subject())

	s.NoError(service.SetName("qq"))
	s.NoError(service.SetSubject("qq.>"))

	s.Nil(a.Exports().Services().Get("q.>"))
	s.Nil(a.Exports().Services().GetByName("q"))
	s.NotNil(a.Exports().Services().Get("qq.>"))
	s.NotNil(a.Exports().Services().GetByName("qq"))

	stream, err := a.Exports().Streams().Add("s", "s.>")
	s.NoError(err)
	s.Equal("s", stream.Name())
	s.Equal("s.>", stream.Subject())

	s.NoError(stream.SetName("ss"))
	s.NoError(stream.SetSubject("ss.>"))

	s.Nil(a.Exports().Streams().Get("s.>"))
	s.Nil(a.Exports().Streams().GetByName("s"))
	s.NotNil(a.Exports().Streams().Get("ss.>"))
	s.NotNil(a.Exports().Streams().GetByName("ss"))
}

func (s *ProviderSuite) Test_ExportDescription() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)
	a := s.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	s.NoError(err)
	s.NoError(service.SetDescription("desc"))
	s.Equal("desc", service.Description())

	stream, err := a.Exports().Streams().Add("s", "s.>")
	s.NoError(err)
	s.NoError(stream.SetDescription("desc"))
	s.Equal("desc", stream.Description())

	s.NoError(auth.Commit())
	s.NoError(auth.Reload())

	a = s.GetAccount(auth, "O", "A")
	service = a.Exports().Services().Get("q.>")
	s.NotNil(service)
	s.Equal("desc", service.Description())

	stream = a.Exports().Streams().Get("s.>")
	s.NotNil(stream)
	s.Equal("desc", stream.Description())
}

func (s *ProviderSuite) Test_ExportInfoURL() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)
	a := s.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	s.NoError(err)
	s.NoError(service.SetInfoURL("https://service.com"))
	s.Equal("https://service.com", service.InfoURL())

	stream, err := a.Exports().Streams().Add("s", "s.>")
	s.NoError(err)
	s.NoError(stream.SetInfoURL("https://stream.com"))
	s.Equal("https://stream.com", stream.InfoURL())

	s.NoError(auth.Commit())
	s.NoError(auth.Reload())

	a = s.GetAccount(auth, "O", "A")
	service = a.Exports().Services().Get("q.>")
	s.NotNil(service)
	s.Equal("https://service.com", service.InfoURL())

	stream = a.Exports().Streams().Get("s.>")
	s.NotNil(stream)
	s.Equal("https://stream.com", stream.InfoURL())

}

func (s *ProviderSuite) Test_ExportAccountTokenPosition() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)
	a := s.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.*")
	s.NoError(err)
	s.NoError(service.SetAccountTokenPosition(2))
	s.Equal(uint(2), service.AccountTokenPosition())

	stream, err := a.Exports().Streams().Add("s", "s.*")
	s.NoError(err)
	s.NoError(stream.SetAccountTokenPosition(2))
	s.Equal(uint(2), stream.AccountTokenPosition())

	s.NoError(auth.Commit())
	s.NoError(auth.Reload())

	a = s.GetAccount(auth, "O", "A")
	service = a.Exports().Services().Get("q.*")
	s.NotNil(service)
	s.Equal(uint(2), service.AccountTokenPosition())

	stream = a.Exports().Streams().Get("s.*")
	s.NotNil(stream)
	s.Equal(uint(2), stream.AccountTokenPosition())
}

func (s *ProviderSuite) Test_ExportAccountTokenPositionRequiresWildcards() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)
	a := s.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.a")
	s.NoError(err)
	s.Error(service.SetAccountTokenPosition(2))

	stream, err := a.Exports().Streams().Add("s", "s.a")
	s.NoError(err)
	s.Error(stream.SetAccountTokenPosition(2))
}
