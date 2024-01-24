package tests

import authb "github.com/synadia-io/jwt-auth-builder.go"

func (t *ProviderSuite) Test_ServiceRequiresName() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	operators := auth.Operators()
	t.Empty(operators.List())

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	_, err = a.Exports().Services().Add("", "q.foo.>")
	t.Error(err)
}

func (t *ProviderSuite) Test_StreamRequiresName() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	operators := auth.Operators()
	t.Empty(operators.List())

	a := t.MaybeCreate(auth, "O", "A")
	t.NotNil(a)

	_, err = a.Exports().Streams().Add("", "t.>")
	t.Error(err)
}

func (t *ProviderSuite) Test_ServiceRequiresSubject() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	operators := auth.Operators()
	t.Empty(operators.List())

	o, err := operators.Add("O")
	t.NoError(err)
	t.NotNil(o)

	a, err := o.Accounts().Add("A")
	t.NoError(err)
	t.NotNil(a)

	_, err = a.Exports().Services().Add("name", "")
	t.Error(err)
}

func (t *ProviderSuite) Test_StreamRequiresSubject() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	operators := auth.Operators()
	t.Empty(operators.List())

	o, err := operators.Add("O")
	t.NoError(err)
	t.NotNil(o)

	a, err := o.Accounts().Add("A")
	t.NoError(err)
	t.NotNil(a)

	_, err = a.Exports().Streams().Add("name", "")
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
	service = a.Exports().Services().Get("q.>")
	t.NotNil(service)
	t.True(service.TokenRequired())

	stream = a.Exports().Streams().Get("t.>")
	t.NotNil(stream)
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

	t.Nil(a.Exports().Services().Get("q.>"))
	t.Nil(a.Exports().Services().GetByName("q"))
	t.NotNil(a.Exports().Services().Get("qq.>"))
	t.NotNil(a.Exports().Services().GetByName("qq"))

	stream, err := a.Exports().Streams().Add("s", "t.>")
	t.NoError(err)
	t.Equal("s", stream.Name())
	t.Equal("t.>", stream.Subject())

	t.NoError(stream.SetName("ss"))
	t.NoError(stream.SetSubject("st.>"))

	t.Nil(a.Exports().Streams().Get("t.>"))
	t.Nil(a.Exports().Streams().GetByName("s"))
	t.NotNil(a.Exports().Streams().Get("st.>"))
	t.NotNil(a.Exports().Streams().GetByName("ss"))
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
	service = a.Exports().Services().Get("q.>")
	t.NotNil(service)
	t.Equal("desc", service.Description())

	stream = a.Exports().Streams().Get("t.>")
	t.NotNil(stream)
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
	service = a.Exports().Services().Get("q.>")
	t.NotNil(service)
	t.Equal("https://service.com", service.InfoURL())

	stream = a.Exports().Streams().Get("t.>")
	t.NotNil(stream)
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
	service = a.Exports().Services().Get("q.*")
	t.NotNil(service)
	t.Equal(uint(2), service.AccountTokenPosition())

	stream = a.Exports().Streams().Get("t.*")
	t.NotNil(stream)
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
