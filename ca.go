package dvgoca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/davidvanlaatum/dvgoutils"
	"github.com/davidvanlaatum/dvgoutils/logging"
)

const SerialBitLength = 128
const maxSerialAttempts = 10

type CANotInitializedError struct {
}

func (e CANotInitializedError) Error() string {
	return "CA is not initialized"
}

type NoCACertError struct {
}

func (e NoCACertError) Error() string {
	return "no CA certificate in store"
}

type CertificateCreator func(rand io.Reader, template, parent *x509.Certificate, pub, priv interface{}) ([]byte, error)
type CertificateParser func(der []byte) (*x509.Certificate, error)
type PrivateKeyMarshaller func(key any) ([]byte, error)
type PKCS8PrivateKeyParser func(der []byte) (any, error)

type CA struct {
	store                Store
	rand                 io.Reader
	timeSource           TimeSource
	privateKey           crypto.Signer
	certificate          *x509.Certificate
	createCertificate    CertificateCreator
	parseCertificate     CertificateParser
	marshalPrivateKey    PrivateKeyMarshaller
	parsePKCS8PrivateKey PKCS8PrivateKeyParser
}

type CAConfig func(*CA)

func WithRand(rand io.Reader) CAConfig {
	return func(ca *CA) {
		ca.rand = rand
	}
}

type TimeSource func() time.Time

func WithTimeSource(timeSource TimeSource) CAConfig {
	return func(ca *CA) {
		ca.timeSource = timeSource
	}
}

func WithCertificateCreator(creator CertificateCreator) CAConfig {
	return func(ca *CA) {
		ca.createCertificate = creator
	}
}

func WithCertificateParser(parser CertificateParser) CAConfig {
	return func(ca *CA) {
		ca.parseCertificate = parser
	}
}

func WithPrivateKeyMarshaller(marshaller PrivateKeyMarshaller) CAConfig {
	return func(ca *CA) {
		ca.marshalPrivateKey = marshaller
	}
}

func WithPKCS8PrivateKeyParser(parser PKCS8PrivateKeyParser) CAConfig {
	return func(ca *CA) {
		ca.parsePKCS8PrivateKey = parser
	}
}

func NewCA(store Store, cfg ...CAConfig) *CA {
	c := &CA{
		store:                store,
		rand:                 rand.Reader,
		timeSource:           time.Now,
		createCertificate:    x509.CreateCertificate,
		parseCertificate:     x509.ParseCertificate,
		marshalPrivateKey:    x509.MarshalPKCS8PrivateKey,
		parsePKCS8PrivateKey: x509.ParsePKCS8PrivateKey,
	}
	for _, f := range cfg {
		f(c)
	}
	return c
}

func (ca *CA) GetCACertificate() *x509.Certificate {
	return ca.certificate
}

func (ca *CA) Init(ctx context.Context, gen KeyGenerator, subject pkix.Name) (err error) {
	l := logging.FromContext(ctx)
	l.InfoContext(ctx, "initializing new CA")
	if ca.privateKey, err = gen.NewKey(ca.rand); err != nil {
		return
	}
	now := ca.timeSource()
	template := &x509.Certificate{
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour*24*365*10 - time.Second),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	if template.SerialNumber, err = ca.newSerial(); err != nil {
		return errors.WithStack(err)
	}
	if err = ca.fillSubjectKeyId(template, ca.privateKey.Public()); err != nil {
		return
	}
	template.AuthorityKeyId = template.SubjectKeyId
	l.InfoContext(ctx, "generating CA certificate", "subject", template.Subject.String(), "not_before", template.NotBefore, "not_after", template.NotAfter, "serial", template.SerialNumber)

	var certBytes []byte
	if certBytes, err = ca.createCertificate(ca.rand, template, template, ca.privateKey.Public(), ca.privateKey); err != nil {
		return errors.WithStack(err)
	}

	l.InfoContext(ctx, "created CA certificate", "len", len(certBytes))

	if ca.certificate, err = ca.parseCertificate(certBytes); err != nil {
		return errors.WithStack(err)
	}

	certInfo := &CertificateInfo{
		Certificate:      ca.certificate,
		Status:           CertificateStatusValid,
		CurrentCACert:    true,
		CertificateBytes: certBytes,
	}

	if certInfo.PrivateKeyBytes, err = ca.marshalPrivateKey(ca.privateKey); err != nil {
		return errors.WithStack(err)
	}

	l.InfoContext(ctx, "adding CA certificate to store")

	if err = ca.store.Add(ctx, certInfo); err != nil {
		return
	}
	l.InfoContext(ctx, "done initializing CA")
	return
}

func (ca *CA) Load(ctx context.Context) (err error) {
	l := logging.FromContext(ctx)
	l.InfoContext(ctx, "loading CA from store")
	var certInfo *CertificateInfo
	if certInfo, err = ca.store.Find(ctx, CertFindOptions{CurrentCACert: dvgoutils.Ptr(true)}); err != nil {
		return
	}
	if certInfo == nil {
		return errors.New("no current CA certificate found in store")
	}
	l.InfoContext(ctx, "found CA certificate", "len", len(certInfo.CertificateBytes))
	var key any
	if key, err = ca.parsePKCS8PrivateKey(certInfo.PrivateKeyBytes); err != nil {
		return errors.WithStack(err)
	}
	var ok bool
	if ca.privateKey, ok = key.(crypto.Signer); !ok {
		return errors.New("private key in store is not a crypto.Signer")
	}
	ca.certificate = certInfo.Certificate
	l.InfoContext(ctx, "loaded CA")
	return
}

func (ca *CA) fillSubjectKeyId(cert *x509.Certificate, publicKey crypto.PublicKey) (err error) {
	var pubBytes []byte
	if pubBytes, err = x509.MarshalPKIXPublicKey(publicKey); err != nil {
		return errors.WithStack(err)
	}
	idHash := sha256.Sum256(pubBytes)
	cert.SubjectKeyId = idHash[:]
	return
}

func (ca *CA) newSerial() (serialNumber *big.Int, err error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), SerialBitLength)
	if serialNumber, err = rand.Int(ca.rand, serialNumberLimit); err != nil {
		return nil, errors.WithStack(err)
	}
	return
}

func (ca *CA) SignCertificateRequest(ctx context.Context, csr *x509.CertificateRequest) (signed *x509.Certificate, err error) {
	now := ca.timeSource()
	if err = csr.CheckSignature(); err != nil {
		return nil, errors.WithStack(err)
	}
	return ca.SignCertificate(ctx, &x509.Certificate{
		Subject:               csr.Subject,
		NotBefore:             now,
		NotAfter:              now.AddDate(1, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
	}, csr.PublicKey)
}

func (ca *CA) SignCertificate(ctx context.Context, cert *x509.Certificate, publicKey crypto.PublicKey) (signed *x509.Certificate, err error) {
	if ca.privateKey == nil || ca.certificate == nil {
		return nil, errors.WithStack(CANotInitializedError{})
	}
	if err = ca.fillSubjectKeyId(cert, publicKey); err != nil {
		return
	}
	cert.AuthorityKeyId = ca.certificate.SubjectKeyId
	l := logging.FromContext(ctx)
	l.InfoContext(ctx, "signing certificate", "subject", cert.Subject.String(), "not_before", cert.NotBefore, "not_after", cert.NotAfter)
	for i := 0; i < maxSerialAttempts; i++ {
		if cert.SerialNumber, err = ca.newSerial(); err != nil {
			return nil, err
		}
		var certBytes []byte
		if certBytes, err = ca.createCertificate(ca.rand, cert, ca.certificate, publicKey, ca.privateKey); err != nil {
			return nil, errors.WithStack(err)
		}

		certInfo := &CertificateInfo{
			Status:           CertificateStatusValid,
			CurrentCACert:    false,
			CertificateBytes: certBytes,
		}

		if certInfo.Certificate, err = ca.parseCertificate(certBytes); err != nil {
			return nil, errors.WithStack(err)
		}

		if err = ca.store.Add(ctx, certInfo); errors.Is(err, DuplicateSerialError{}) {
			l.InfoContext(ctx, "duplicate serial number, retrying", "serial", cert.SerialNumber)
			continue
		} else if err != nil {
			return
		}
		signed = certInfo.Certificate
		return
	}
	return nil, errors.New("max attempts to find a free serial number exceeded")
}

func (ca *CA) CheckForExpired(ctx context.Context) (err error) {
	l := logging.FromContext(ctx)
	return ca.store.BulkUpdate(ctx, CertFindOptions{
		Status:      dvgoutils.Ptr(CertificateStatusValid),
		NotAfterEnd: dvgoutils.Ptr(ca.timeSource()),
	}, func(ctx context.Context, cert *CertificateInfo) (*CertificateInfo, error) {
		l.InfoContext(ctx, "found expired certificate, marking as expired", "serial", cert.Certificate.SerialNumber, "subject", cert.Certificate.Subject.String(), "not_after", cert.Certificate.NotAfter)
		cert.Status = CertificateStatusExpired
		return cert, nil
	})
}
