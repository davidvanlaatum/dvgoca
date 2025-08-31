package dvgoca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"io"

	"github.com/cockroachdb/errors"
)

type KeyGenerator interface {
	NewKey(rand io.Reader) (crypto.Signer, error)
}

type ECDSAKeyGenerator struct {
	curve elliptic.Curve
}

func NewECDSAKeyGenerator(curve elliptic.Curve) *ECDSAKeyGenerator {
	return &ECDSAKeyGenerator{curve: curve}
}

func (kg *ECDSAKeyGenerator) NewKey(rand io.Reader) (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(kg.curve, rand)
	return key, errors.WithStack(err)
}

type Ed25519KeyGenerator struct {
}

func NewEd25519KeyGenerator() *Ed25519KeyGenerator {
	return &Ed25519KeyGenerator{}
}

func (kg *Ed25519KeyGenerator) NewKey(rand io.Reader) (crypto.Signer, error) {
	_, key, err := ed25519.GenerateKey(rand)
	return key, errors.WithStack(err)
}
