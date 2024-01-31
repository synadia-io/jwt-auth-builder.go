package tests

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/require"
)

type NatsServer struct {
	sync.Mutex
	t      *testing.T
	Server *server.Server
	Url    string
	Conns  []*nats.Conn
}

func NewNatsServer(t *testing.T, opts *server.Options) *NatsServer {
	ns, u := SetupNatsServer(t, opts)
	return &NatsServer{
		t:      t,
		Server: ns,
		Url:    u,
	}
}

func (ts *NatsServer) Connect() *nats.Conn {
	nc, err := ts.MaybeConnect(nil)
	require.NoError(ts.t, err)
	return nc
}

func (ts *NatsServer) MaybeConnect(options ...nats.Option) (*nats.Conn, error) {
	ts.Lock()
	defer ts.Unlock()
	nc, err := nats.Connect(ts.Url, options...)
	if err == nil {
		ts.Conns = append(ts.Conns, nc)
	}
	return nc, err
}

func (ts *NatsServer) NewKv(bucket string) jetstream.KeyValue {
	nc := ts.Connect()
	js, err := jetstream.New(nc)
	require.NoError(ts.t, err)

	kv, err := js.CreateKeyValue(context.Background(), jetstream.KeyValueConfig{
		Bucket: bucket,
	})
	require.NoError(ts.t, err)
	return kv
}

func (ts *NatsServer) Shutdown() {
	ts.Lock()
	defer ts.Unlock()
	for _, c := range ts.Conns {
		c.Close()
	}
	ts.Server.Shutdown()
}

func defaultNatsOptions(tempDir string) *server.Options {
	return &server.Options{
		Host:                  "127.0.0.1",
		Port:                  -1,
		NoLog:                 true,
		NoSigs:                true,
		MaxControlLine:        4096,
		DisableShortFirstPing: true,
		JetStream:             true,
		StoreDir:              tempDir,
	}
}

func SetupNatsServer(t *testing.T, opts *server.Options) (*server.Server, string) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "nhg_test")
	require.NoError(t, err)

	if opts == nil {
		opts = defaultNatsOptions(tempDir)
	}

	s, err := server.NewServer(opts)
	require.NoError(t, err)

	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatalf("Unable to start NATS Server in Go Routine")
	}

	ports := s.PortsInfo(time.Second)

	return s, ports.Nats[0]
}
