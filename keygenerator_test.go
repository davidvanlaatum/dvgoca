package dvgoca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/require"
)

func TestECDSAKeyGenerator_NewKey(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	g := NewECDSAKeyGenerator(elliptic.P224())
	key, err := g.NewKey(rand.Reader)
	r.NoError(err)
	r.NotNil(key)
	r.IsType(&ecdsa.PrivateKey{}, key)
	r.Equal(elliptic.P224(), key.Public().(*ecdsa.PublicKey).Curve)
}

type errReader struct{}

func (e *errReader) Read([]byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestECDSAKeyGenerator_NewKeyError(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	g := NewECDSAKeyGenerator(elliptic.P224())
	key, err := g.NewKey(&errReader{})
	r.ErrorContains(err, "read error")
	r.NotNil(errors.GetReportableStackTrace(err))
	r.Nil(key)
}

func TestEd25519KeyGenerator_NewKey(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	g := NewEd25519KeyGenerator()
	key, err := g.NewKey(rand.Reader)
	r.NoError(err)
	r.NotNil(key)
	r.IsType(ed25519.PrivateKey{}, key)
}

func TestEd25519KeyGenerator_NewKeyError(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	g := NewEd25519KeyGenerator()
	key, err := g.NewKey(&errReader{})
	r.ErrorContains(err, "read error")
	r.NotNil(errors.GetReportableStackTrace(err))
	r.Nil(key)
}
