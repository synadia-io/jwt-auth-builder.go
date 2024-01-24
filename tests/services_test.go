package tests

import (
	"errors"
	"time"

	"github.com/nats-io/nkeys"
	authb "github.com/synadia-io/jwt-auth-builder.go"
)

func (s *ProviderSuite) Test_ServiceRequiresName() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	operators := auth.Operators()
	s.Empty(operators.List())

	a := s.MaybeCreate(auth, "O", "A")
	s.NotNil(a)

	_, err = a.Exports().Services().AddService("", "q.foo.>")
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

	_, err = a.Exports().Services().AddService("name", "")
	s.Error(err)
}

func (s *ProviderSuite) Test_AddService() {
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

	service, err := authb.NewService("q", "q.*")
	s.NoError(err)

	err = a.Exports().Services().AddServiceWithConfig(service)
	s.NoError(err)

	service = a.Exports().Services().GetService("q.*")
	s.NotNil(service)
	s.Equal("q", service.Name())
	s.Equal("q.*", service.Subject())
}

func (s *ProviderSuite) Test_ServiceCrud() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	a := s.MaybeCreate(auth, "O", "A")
	s.Len(a.Exports().Services().ListServices(), 0)

	service, err := a.Exports().Services().AddService("foos", "q.foo.>")
	s.NoError(err)
	s.NotNil(service)
	s.Equal("foos", service.Name())
	s.Equal("q.foo.>", service.Subject())
	s.NoError(service.SetTokenRequired(true))
	s.Equal(true, service.TokenRequired())

	s.NoError(auth.Commit())
	s.NoError(auth.Reload())

	a = s.GetAccount(auth, "O", "A")
	s.NotNil(a)

	services := a.Exports().Services().ListServices()
	s.Len(services, 1)
	s.Equal("foos", services[0].Name())
	s.Equal("q.foo.>", services[0].Subject())
	s.Equal(true, services[0].TokenRequired())

	s.Nil(a.Exports().Services().GetServiceByName("foo"))

	service = a.Exports().Services().GetServiceByName("foos")
	s.NotNil(service)

	service = a.Exports().Services().GetService("q.foo.>")
	s.NotNil(service)

	s.NoError(service.SetName("bar"))
	s.NoError(service.SetTokenRequired(false))
	s.NoError(service.SetSubject("bar.*"))
	s.NoError(auth.Commit())
	s.NoError(auth.Reload())

	services = a.Exports().Services().ListServices()
	s.Len(services, 1)
	s.Equal("bar", services[0].Name())
	s.Equal("bar.*", services[0].Subject())
	s.Equal(false, services[0].TokenRequired())
}

func (s *ProviderSuite) Test_StreamCrud() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	a := s.MaybeCreate(auth, "O", "A")
	s.Len(a.Exports().Streams().ListStreams(), 0)

	stream, err := a.Exports().Streams().AddStream("foos", "q.foo.>")
	s.NoError(err)
	s.NotNil(stream)
	s.Equal("foos", stream.Name())
	s.Equal("q.foo.>", stream.Subject())
	s.NoError(stream.SetTokenRequired(true))
	s.Equal(true, stream.TokenRequired())

	s.NoError(auth.Commit())
	s.NoError(auth.Reload())

	a = s.GetAccount(auth, "O", "A")
	s.NotNil(a)

	streams := a.Exports().Streams().ListStreams()
	s.Len(streams, 1)
	s.Equal("foos", streams[0].Name())
	s.Equal("q.foo.>", streams[0].Subject())
	s.Equal(true, streams[0].TokenRequired())

	s.Nil(a.Exports().Streams().GetStreamByName("foo"))

	stream = a.Exports().Streams().GetStreamByName("foos")
	s.NotNil(stream)

	stream = a.Exports().Streams().GetStream("q.foo.>")
	s.NotNil(stream)

	s.NoError(stream.SetName("bar"))
	s.NoError(stream.SetTokenRequired(false))
	s.NoError(stream.SetSubject("bar.*"))
	s.NoError(auth.Commit())
	s.NoError(auth.Reload())

	streams = a.Exports().Streams().ListStreams()
	s.Len(streams, 1)
	s.Equal("bar", streams[0].Name())
	s.Equal("bar.*", streams[0].Subject())
	s.Equal(false, streams[0].TokenRequired())
}

func (s *ProviderSuite) Test_SetStream() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	a := s.MaybeCreate(auth, "O", "A")
	s.Len(a.Exports().Streams().ListStreams(), 0)

	_, err = a.Exports().Services().AddService("a", "q.a.>")
	s.NoError(err)

	_, err = a.Exports().Streams().AddStream("a", "a.>")
	s.NoError(err)

	// empty set clears
	err = a.Exports().Streams().SetStreams(nil)
	s.NoError(err)
	s.Len(a.Exports().Streams().ListStreams(), 0)
	s.Len(a.Exports().Services().ListServices(), 1)

	service1, err := authb.NewService("q", "q")
	s.NoError(err)
	service2, err := authb.NewService("qq", "qq")
	s.NoError(err)

	err = a.Exports().Services().SetServices(service1, service2)
	s.NoError(err)
	s.Nil(a.Exports().Services().GetService("q.a.>"))
	services := a.Exports().Services().ListServices()
	s.Len(services, 2)
}

func (s *ProviderSuite) Test_ServiceRevocationCrud() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	a := s.MaybeCreate(auth, "O", "A")
	s.NotNil(a)
	s.Len(a.Exports().Services().ListServices(), 0)

	service, err := a.Exports().Services().AddService("foos", "q.foo.>")
	s.NoError(err)
	s.NotNil(service)
	s.Equal("foos", service.Name())
	s.Equal("q.foo.>", service.Subject())

	// Let's create a revocation for an account
	k, _ := authb.KeyFor(nkeys.PrefixByteAccount)

	// Since the export is public this fails
	err = service.Revocations().Add(k.Public, time.Now())
	s.Error(err)
	s.True(errors.Is(err, authb.ErrRevocationPublicExportsNotAllowed))

	// Require a token, and revocation is now added
	err = service.SetTokenRequired(true)
	s.NoError(err)
	err = service.Revocations().Add(k.Public, time.Now())
	s.NoError(err)

	s.NoError(auth.Commit())
	s.NoError(auth.Reload())

	// reload the configuration, find the service
	a = s.GetAccount(auth, "O", "A")
	s.NotNil(a)
	service = a.Exports().Services().GetServiceByName("foos")
	s.NotNil(service)

	revocations := service.Revocations()

	// check the revocation is there
	s.Len(revocations.List(), 1)
	tf, err := revocations.HasRevocation("*")
	s.Nil(err)
	s.False(tf)

	// try a key that is not supported
	uk, _ := authb.KeyFor(nkeys.PrefixByteUser)
	tf, err = revocations.HasRevocation(uk.Public)
	s.Error(err)
	s.False(tf)

	// find the key we want
	tf, err = revocations.HasRevocation(k.Public)
	s.NoError(err)
	s.True(tf)

	// test listing
	entries := revocations.List()
	s.Len(entries, 1)
	s.Equal(k.Public, entries[0].PublicKey())

	// try to remove it - it doesn't exist
	ok, err := revocations.Delete("*")
	s.NoError(err)
	s.False(ok)

	// add it
	s.NoError(revocations.Add("*", time.Now()))
	entries = revocations.List()
	s.Len(entries, 2)

	tf, _ = revocations.HasRevocation(k.Public)
	s.True(tf)
	tf, _ = revocations.HasRevocation("*")
	s.True(tf)

	// verify the list contains them
	var wildcard authb.RevocationEntry
	var account authb.RevocationEntry
	for _, e := range entries {
		if e.PublicKey() == "*" {
			wildcard = e
		} else {
			account = e
		}
	}
	s.NotNil(wildcard)
	s.NotNil(account)

	tf, err = revocations.Delete(k.Public)
	s.NoError(err)
	s.True(tf)

	entries = revocations.List()
	s.Len(entries, 1)
	tf, _ = revocations.HasRevocation(k.Public)
	s.False(tf)

	// add them both
	s.NoError(revocations.SetRevocations([]authb.RevocationEntry{account, wildcard}))
	entries = revocations.List()
	s.Len(entries, 2)

	// clear
	s.NoError(revocations.SetRevocations(nil))
	entries = revocations.List()
	s.Len(entries, 0)

	// yesterday
	s.NoError(revocations.Add(k.Public, time.Now().Add(time.Hour*-24)))

	// add a wildcard as of now (includes and rejects the previous revocation
	s.NoError(revocations.Add("*", time.Now()))
	entries = revocations.List()
	s.Len(entries, 2)

	// wildcard includes yesterday
	removed, err := revocations.Compact()
	s.NoError(err)
	s.Len(removed, 1)
	s.Equal(k.Public, removed[0].PublicKey())
}
