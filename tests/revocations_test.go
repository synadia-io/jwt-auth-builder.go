package tests

import (
	"errors"
	"time"

	authb "github.com/synadia-io/jwt-auth-builder.go"
)

func (t *ProviderSuite) Test_ExportRevocationRequiresToken() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.True(errors.Is(service.Revocations().Add("*", time.Now()), authb.ErrRevocationPublicExportsNotAllowed))

	t.NoError(service.SetTokenRequired(true))
	t.NoError(service.Revocations().Add("*", time.Now()))

	stream, err := a.Exports().Streams().Add("t", "t.>")
	t.NoError(err)
	t.True(errors.Is(stream.Revocations().Add("*", time.Now()), authb.ErrRevocationPublicExportsNotAllowed))

	t.NoError(stream.SetTokenRequired(true))
	t.NoError(stream.Revocations().Add("*", time.Now()))
}

func (t *ProviderSuite) Test_ExportRevocationRequiresAccountToken() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	uk := t.UserKey()
	ak := t.AccountKey()

	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.NoError(service.SetTokenRequired(true))
	t.Error(service.Revocations().Add(uk.Public, time.Now()))
	t.NoError(service.Revocations().Add(ak.Public, time.Now()))

	stream, err := a.Exports().Streams().Add("t", "t.>")
	t.NoError(err)
	t.NoError(stream.SetTokenRequired(true))
	t.Error(stream.Revocations().Add(uk.Public, time.Now()))
	t.NoError(stream.Revocations().Add(ak.Public, time.Now()))

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	a = t.GetAccount(auth, "O", "A")

	service, ok := a.Exports().Services().Get("q.>")
	t.True(ok)
	revocations := service.Revocations().List()
	t.Len(revocations, 1)
	t.Equal(ak.Public, revocations[0].PublicKey())

	stream, ok = a.Exports().Streams().Get("t.>")
	t.True(ok)
	revocations = stream.Revocations().List()
	t.Len(revocations, 1)
	t.Equal(ak.Public, revocations[0].PublicKey())
}

func (t *ProviderSuite) Test_ExportRevocationWildCardIsAllowed() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.NoError(service.SetTokenRequired(true))
	t.NoError(service.Revocations().Add("*", time.Now()))

	stream, err := a.Exports().Streams().Add("t", "t.>")
	t.NoError(err)
	t.NoError(stream.SetTokenRequired(true))
	t.NoError(stream.Revocations().Add("*", time.Now()))

	t.NoError(auth.Commit())
	t.NoError(auth.Reload())

	a = t.GetAccount(auth, "O", "A")

	service, ok := a.Exports().Services().Get("q.>")
	t.True(ok)
	revocations := service.Revocations().List()
	t.Len(revocations, 1)
	t.Equal("*", revocations[0].PublicKey())

	stream, ok = a.Exports().Streams().Get("t.>")
	t.True(ok)
	revocations = stream.Revocations().List()
	t.Len(revocations, 1)
	t.Equal("*", revocations[0].PublicKey())
}

func (t *ProviderSuite) testRevocationKeyChecks(r authb.Revocable) {
	revocations := r.Revocations()
	t.Len(revocations.List(), 0)

	t.NoError(revocations.Add("*", time.Now()))
	t.True(revocations.Contains("*"))

	_, err := revocations.Contains("hello")
	t.Error(err)

	ok, err := revocations.Contains(t.AccountKey().Public)
	t.NoError(err)
	t.False(ok)

	_, err = revocations.Delete("hello")
	t.Error(err)

	ok, err = revocations.Delete(t.AccountKey().Public)
	t.NoError(err)
	t.False(ok)
}

func (t *ProviderSuite) Test_ExportRevocationBadNKeyIsRejected() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.NoError(service.SetTokenRequired(true))
	t.testRevocationKeyChecks(service)

	stream, err := a.Exports().Streams().Add("t", "t.>")
	t.NoError(err)
	t.NoError(stream.SetTokenRequired(true))
	t.testRevocationKeyChecks(stream)
}

func (t *ProviderSuite) testListCrud(r authb.Revocable) {
	revocations := r.Revocations()
	t.Len(revocations.List(), 0)

	t.NoError(revocations.Add("*", time.Now()))
	t.Len(revocations.List(), 1)
	t.True(revocations.Contains("*"))

	err := revocations.Set([]authb.RevocationEntry{
		authb.NewRevocationEntry(t.AccountKey().Public, time.Now()),
		authb.NewRevocationEntry(t.AccountKey().Public, time.Now()),
	})
	t.NoError(err)
	t.Len(revocations.List(), 2)
	t.False(revocations.Contains("*"))

	when := time.Now().Add(time.Hour)
	t.NoError(revocations.Add("*", when))
	t.Len(revocations.List(), 3)

	compact, err := revocations.Compact()
	t.NoError(err)
	t.Len(compact, 2)
	t.Equal("*", revocations.List()[0].PublicKey())
	t.Equal(when.Unix(), revocations.List()[0].At().Unix())

	ok, err := revocations.Delete("*")
	t.True(ok)
	t.NoError(err)
}

func (t *ProviderSuite) Test_ExportRevocationCrud() {
	auth, err := authb.NewAuth(t.Provider)
	t.NoError(err)

	a := t.MaybeCreate(auth, "O", "A")
	service, err := a.Exports().Services().Add("q", "q.>")
	t.NoError(err)
	t.NoError(service.SetTokenRequired(true))
	t.testListCrud(service)

	stream, err := a.Exports().Streams().Add("t", "t.>")
	t.NoError(err)
	t.NoError(stream.SetTokenRequired(true))
	t.testListCrud(stream)
}
