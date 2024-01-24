package tests

import (
	"errors"
	"time"

	authb "github.com/synadia-io/jwt-auth-builder.go"
)

func (s *ProviderSuite) Test_ExportRevocationRequiresToken() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	a := s.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	s.NoError(err)
	s.True(errors.Is(service.Revocations().Add("*", time.Now()), authb.ErrRevocationPublicExportsNotAllowed))

	s.NoError(service.SetTokenRequired(true))
	s.NoError(service.Revocations().Add("*", time.Now()))

	stream, err := a.Exports().Streams().Add("s", "s.>")
	s.NoError(err)
	s.True(errors.Is(stream.Revocations().Add("*", time.Now()), authb.ErrRevocationPublicExportsNotAllowed))

	s.NoError(stream.SetTokenRequired(true))
	s.NoError(stream.Revocations().Add("*", time.Now()))
}

func (s *ProviderSuite) Test_ExportRevocationRequiresAccountToken() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	uk := s.UserKey()
	ak := s.AccountKey()

	a := s.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	s.NoError(err)
	s.NoError(service.SetTokenRequired(true))
	s.Error(service.Revocations().Add(uk.Public, time.Now()))
	s.NoError(service.Revocations().Add(ak.Public, time.Now()))

	stream, err := a.Exports().Streams().Add("s", "s.>")
	s.NoError(err)
	s.NoError(stream.SetTokenRequired(true))
	s.Error(stream.Revocations().Add(uk.Public, time.Now()))
	s.NoError(stream.Revocations().Add(ak.Public, time.Now()))

	s.NoError(auth.Commit())
	s.NoError(auth.Reload())

	a = s.GetAccount(auth, "O", "A")

	service = a.Exports().Services().Get("q.>")
	s.NotNil(service)
	revocations := service.Revocations().List()
	s.Len(revocations, 1)
	s.Equal(ak.Public, revocations[0].PublicKey())

	stream = a.Exports().Streams().Get("s.>")
	s.NotNil(stream)
	revocations = stream.Revocations().List()
	s.Len(revocations, 1)
	s.Equal(ak.Public, revocations[0].PublicKey())
}

func (s *ProviderSuite) Test_ExportRevocationWildCardIsAllowed() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	a := s.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	s.NoError(err)
	s.NoError(service.SetTokenRequired(true))
	s.NoError(service.Revocations().Add("*", time.Now()))

	stream, err := a.Exports().Streams().Add("s", "s.>")
	s.NoError(err)
	s.NoError(stream.SetTokenRequired(true))
	s.NoError(stream.Revocations().Add("*", time.Now()))

	s.NoError(auth.Commit())
	s.NoError(auth.Reload())

	a = s.GetAccount(auth, "O", "A")

	service = a.Exports().Services().Get("q.>")
	s.NotNil(service)
	revocations := service.Revocations().List()
	s.Len(revocations, 1)
	s.Equal("*", revocations[0].PublicKey())

	stream = a.Exports().Streams().Get("s.>")
	s.NotNil(stream)
	revocations = stream.Revocations().List()
	s.Len(revocations, 1)
	s.Equal("*", revocations[0].PublicKey())
}

func (s *ProviderSuite) testRevocationKeyChecks(r authb.Revocable) {
	revocations := r.Revocations()
	s.Len(revocations.List(), 0)

	s.NoError(revocations.Add("*", time.Now()))
	s.True(revocations.Contains("*"))

	_, err := revocations.Contains("hello")
	s.Error(err)

	ok, err := revocations.Contains(s.AccountKey().Public)
	s.NoError(err)
	s.False(ok)

	_, err = revocations.Delete("hello")
	s.Error(err)

	ok, err = revocations.Delete(s.AccountKey().Public)
	s.NoError(err)
	s.False(ok)
}

func (s *ProviderSuite) Test_ExportRevocationBadNKeyIsRejected() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	a := s.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	s.NoError(err)
	s.NoError(service.SetTokenRequired(true))
	s.testRevocationKeyChecks(service)

	stream, err := a.Exports().Streams().Add("s", "s.>")
	s.NoError(err)
	s.NoError(stream.SetTokenRequired(true))
	s.testRevocationKeyChecks(stream)
}

func (s *ProviderSuite) testListCrud(r authb.Revocable) {
	revocations := r.Revocations()
	s.Len(revocations.List(), 0)

	s.NoError(revocations.Add("*", time.Now()))
	s.Len(revocations.List(), 1)
	s.True(revocations.Contains("*"))

	err := revocations.Set([]authb.RevocationEntry{
		authb.NewRevocationEntry(s.AccountKey().Public, time.Now()),
		authb.NewRevocationEntry(s.AccountKey().Public, time.Now()),
	})
	s.NoError(err)
	s.Len(revocations.List(), 2)
	s.False(revocations.Contains("*"))

	when := time.Now().Add(time.Hour)
	s.NoError(revocations.Add("*", when))
	s.Len(revocations.List(), 3)

	compact, err := revocations.Compact()
	s.NoError(err)
	s.Len(compact, 2)
	s.Equal("*", revocations.List()[0].PublicKey())
	s.Equal(when.Unix(), revocations.List()[0].At().Unix())

	ok, err := revocations.Delete("*")
	s.True(ok)
	s.NoError(err)
}

func (s *ProviderSuite) Test_ExportRevocationCrud() {
	auth, err := authb.NewAuth(s.Provider)
	s.NoError(err)

	a := s.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	s.NoError(err)
	s.NoError(service.SetTokenRequired(true))
	s.testListCrud(service)

	stream, err := a.Exports().Streams().Add("s", "s.>")
	s.NoError(err)
	s.NoError(stream.SetTokenRequired(true))
	s.testListCrud(stream)
}
