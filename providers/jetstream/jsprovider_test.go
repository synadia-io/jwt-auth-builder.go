package jetstream

import (
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nuid"
	"github.com/stretchr/testify/require"
	ab "github.com/synadia-io/jwt-auth-builder.go"
)

func Test_JSProvider(t *testing.T) {
	kp, err := nkeys.CreateCurveKeys()
	require.NoError(t, err)

	key, err := kp.Seed()
	require.NoError(t, err)

	bucket := nuid.Next()
	p, err := NewJetstreamProvider("nats://demo.nats.io:4222", bucket, string(key))
	require.NoError(t, err)
	require.NotNil(t, p)

	auth, err := ab.NewAuth(p)
	require.NoError(t, err)
	require.NotNil(t, auth)

	operators := auth.Operators().List()
	require.Empty(t, operators)

	o, err := auth.Operators().Add("O")
	require.NoError(t, err)
	a, err := o.Accounts().Add("A")
	require.NoError(t, err)
	u, err := a.Users().Add("U", "")
	require.NoError(t, err)
	require.NotNil(t, u)
	require.NoError(t, auth.Commit())

	require.NoError(t, auth.Reload())
	o = auth.Operators().Get("O")
	require.NotNil(t, o)
	a = o.Accounts().Get("A")
	require.NotNil(t, "A")
	u = a.Users().Get("U")
	require.NotNil(t, u)

	require.NoError(t, p.(*Provider).Destroy())
}
