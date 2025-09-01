package dvgoca

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/davidvanlaatum/dvgoutils/logging"
	"github.com/davidvanlaatum/dvgoutils/logging/testhandler"
	"github.com/stretchr/testify/require"
)

type dummyRand struct {
	offset bool
	reads  int
}

func (r *dummyRand) Read(b []byte) (n int, err error) {
	defer func() {
		r.reads++
	}()
	o := 0
	if r.offset {
		o = r.reads
	}
	for i := range b {
		b[i] = byte(i + o)
	}
	return len(b), nil
}

func TestCA_Init(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	_ = os.Remove("ca_cert.pem")
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	l.InfoContext(ctx, "go version", slog.String("version", runtime.Version()))
	store := NewInMemoryStore()
	ca := NewCA(store, WithTimeSource(func() time.Time {
		return time.Unix(60, 0)
	}), WithRand(&dummyRand{}))
	subject := pkix.Name{
		Organization:       []string{"Dvca"},
		OrganizationalUnit: []string{"Dvca Root CA"},
		CommonName:         "Dvca Root CA",
	}
	r.NoError(ca.Init(ctx, NewEd25519KeyGenerator(), subject))
	caCert := ca.GetCACertificate()
	b, _ := pem.Decode([]byte(`-----BEGIN CERTIFICATE-----
MIIB0zCCAYWgAwIBAgIPAQIDBAUGBwgJCgsMDQ4PMAUGAytlcDA9MQ0wCwYDVQQK
EwREdmNhMRUwEwYDVQQLEwxEdmNhIFJvb3QgQ0ExFTATBgNVBAMTDER2Y2EgUm9v
dCBDQTAeFw03MDAxMDEwMDAxMDBaFw03OTEyMzAwMDAwNTlaMD0xDTALBgNVBAoT
BER2Y2ExFTATBgNVBAsTDER2Y2EgUm9vdCBDQTEVMBMGA1UEAxMMRHZjYSBSb290
IENBMCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbij
gZswgZgwDgYDVR0PAQH/BAQDAgEGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEF
BQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdDgQiBCCgUIN9hQcFgsz3OUsJiIR8
wxLLiCWbiUiZ9vI5zxeRpTArBgNVHSMEJDAigCCgUIN9hQcFgsz3OUsJiIR8wxLL
iCWbiUiZ9vI5zxeRpTAFBgMrZXADQQATshVBqOrJJfapQA2ojJy1GEfA1t6S+P0T
oTBZ1amR/xxzAhsuY0QrvmFhv2S/Us/CplwP171fybBgxgUUMXAE
-----END CERTIFICATE-----
`))
	expectedCert, err := x509.ParseCertificate(b.Bytes)
	r.NoError(err)
	expectedCert.Raw = nil
	expectedCert.RawTBSCertificate = nil
	expectedCert.Signature = nil
	defer func(b []byte) {
		if t.Failed() {
			if b != nil {
				f, err := os.Create("ca_cert.pem")
				r.NoError(err)
				defer func(f *os.File) {
					r.NoError(f.Close())
				}(f)
				r.NoError(pem.Encode(f, &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: b,
				}))
			} else {
				t.Log("raw cert is nil, not writing to file")
				t.Fail()
			}
		}
	}(caCert.Raw)
	r.Equal(expectedCert.NotBefore, caCert.NotBefore)
	r.Equal(expectedCert.NotAfter, caCert.NotAfter)
	caCert.Raw = nil
	caCert.RawTBSCertificate = nil
	caCert.Signature = nil
	r.NotNil(expectedCert)
	r.Equal(expectedCert, caCert)

	ca2 := NewCA(store)
	r.NoError(ca2.Load(ctx))
	r.Equal(caCert, ca2.GetCACertificate())
	r.Equal(ca.privateKey, ca2.privateKey)
}

func TestCA_SignCertificate(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	_ = os.Remove("cert.pem")
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	store := NewInMemoryStore()
	ca := NewCA(store, WithTimeSource(func() time.Time {
		return time.Unix(10, 0)
	}), WithRand(&dummyRand{offset: true}))
	subject := pkix.Name{
		Organization:       []string{"Dvca"},
		OrganizationalUnit: []string{"Dvca Root CA"},
		CommonName:         "Dvca Root CA",
	}
	r.NoError(ca.Init(ctx, NewEd25519KeyGenerator(), subject))
	caCert := ca.GetCACertificate()
	r.NotNil(caCert)

	certTemplate := &x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"Example Org"},
			OrganizationalUnit: []string{"IT"},
			CommonName:         "example.com",
		},
		NotBefore:             ca.timeSource(),
		NotAfter:              ca.timeSource().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com", "www.example.com"},
	}
	key, err := NewEd25519KeyGenerator().NewKey(&dummyRand{})
	r.NoError(err)
	cert, err := ca.SignCertificate(ctx, certTemplate, key.Public())
	r.NoError(err)
	r.NotNil(cert)
	defer func() {
		if t.Failed() {
			f, err := os.Create("cert.pem")
			r.NoError(err)
			defer func(f *os.File) {
				r.NoError(f.Close())
			}(f)
			r.NoError(pem.Encode(f, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}))
		}
	}()
	r.NoError(cert.CheckSignatureFrom(caCert))
	b, _ := pem.Decode([]byte(`-----BEGIN CERTIFICATE-----
MIIB7DCCAZ6gAwIBAgIQAgMEBQYHCAkKCwwNDg8QETAFBgMrZXAwPTENMAsGA1UE
ChMERHZjYTEVMBMGA1UECxMMRHZjYSBSb290IENBMRUwEwYDVQQDEwxEdmNhIFJv
b3QgQ0EwHhcNNzAwMTAxMDAwMDEwWhcNNzEwMTAxMDAwMDEwWjA5MRQwEgYDVQQK
EwtFeGFtcGxlIE9yZzELMAkGA1UECxMCSVQxFDASBgNVBAMTC2V4YW1wbGUuY29t
MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbijgbcw
gbQwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwKQYDVR0OBCIEIKBQg32FBwWCzPc5SwmIhHzDEsuIJZuJSJn28jnPF5Gl
MCsGA1UdIwQkMCKAIKBQg32FBwWCzPc5SwmIhHzDEsuIJZuJSJn28jnPF5GlMCcG
A1UdEQQgMB6CC2V4YW1wbGUuY29tgg93d3cuZXhhbXBsZS5jb20wBQYDK2VwA0EA
TSTskVCib/8Zx7hz8i2KUwtNhsbVM4mH8qqEWYU23GSAlM0T4wm4xkxPaBcgZ7No
7mivZzUPXLMhXR+RSl4TDg==
-----END CERTIFICATE-----
`))
	expectedCert, err := x509.ParseCertificate(b.Bytes)
	r.NoError(err)
	r.NotNil(expectedCert)
	r.Equal(expectedCert, cert)
}

func TestCA_SignCertificateMaxAttempts(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	store := NewInMemoryStore()
	ca := NewCA(store, WithTimeSource(func() time.Time {
		return time.Unix(10, 0)
	}), WithRand(&dummyRand{}))
	subject := pkix.Name{
		Organization:       []string{"Dvca"},
		OrganizationalUnit: []string{"Dvca Root CA"},
		CommonName:         "Dvca Root CA",
	}
	r.NoError(ca.Init(ctx, NewEd25519KeyGenerator(), subject))
	caCert := ca.GetCACertificate()
	r.NotNil(caCert)
	certTemplate := &x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"Example Org"},
			OrganizationalUnit: []string{"IT"},
			CommonName:         "example.com",
		},
		NotBefore:             ca.timeSource(),
		NotAfter:              ca.timeSource().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com", "www.example.com"},
	}
	key, err := NewEd25519KeyGenerator().NewKey(&dummyRand{})
	r.NoError(err)
	_, err = ca.SignCertificate(ctx, certTemplate, key.Public())
	r.ErrorContains(err, "max attempts to find a free serial number exceeded")
	r.NotNil(errors.GetReportableStackTrace(err))
}

func TestCA_CheckForExpired(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	store := NewInMemoryStore()
	ca := NewCA(store, WithTimeSource(func() time.Time {
		return time.Unix(10, 0)
	}))
	r.NoError(store.Add(ctx, &CertificateInfo{
		Status: CertificateStatusValid,
		Certificate: &x509.Certificate{
			SerialNumber: big.NewInt(10),
			NotAfter:     time.Unix(5, 0),
		},
	}))
	r.NoError(store.Add(ctx, &CertificateInfo{
		Status: CertificateStatusValid,
		Certificate: &x509.Certificate{
			SerialNumber: big.NewInt(11),
			NotAfter:     time.Unix(15, 0),
		},
	}))
	r.NoError(ca.CheckForExpired(ctx))
	cert, err := store.Find(ctx, CertFindOptions{
		SerialNumber: big.NewInt(10),
	})
	r.NoError(err)
	r.Equal(CertificateStatusExpired, cert.Status)
	cert, err = store.Find(ctx, CertFindOptions{
		SerialNumber: big.NewInt(11),
	})
	r.NoError(err)
	r.Equal(CertificateStatusValid, cert.Status)
}

func TestCA_SignCertificateRequest(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	store := NewInMemoryStore()
	ca := NewCA(store, WithTimeSource(func() time.Time {
		return time.Unix(10, 0)
	}), WithRand(&dummyRand{offset: true}))
	subject := pkix.Name{
		Organization:       []string{"Dvca"},
		OrganizationalUnit: []string{"Dvca Root CA"},
		CommonName:         "Dvca Root CA",
	}
	r.NoError(ca.Init(ctx, NewEd25519KeyGenerator(), subject))
	reqKey, err := NewEd25519KeyGenerator().NewKey(&dummyRand{offset: true})
	r.NoError(err)
	reqBytes, err := x509.CreateCertificateRequest(&dummyRand{offset: true}, &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Example Org"},
			OrganizationalUnit: []string{"IT"},
			CommonName:         "example.com",
		},
		DNSNames: []string{"example.com", "www.example.com"},
	}, reqKey)
	r.NoError(err)
	req, err := x509.ParseCertificateRequest(reqBytes)
	r.NoError(err)
	cert, err := ca.SignCertificateRequest(ctx, req)
	r.NoError(err)
	defer func(b []byte) {
		if t.Failed() {
			f, err := os.Create("cert.pem")
			r.NoError(err)
			defer func(f *os.File) {
				r.NoError(f.Close())
			}(f)
			r.NoError(pem.Encode(f, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: b,
			}))
		}
	}(cert.Raw)
	r.NoError(cert.CheckSignatureFrom(ca.GetCACertificate()))
	cert.Raw = nil
	cert.RawTBSCertificate = nil
	cert.Signature = nil
	b, _ := pem.Decode([]byte(`-----BEGIN CERTIFICATE-----
MIIB9jCCAaigAwIBAgIQAgMEBQYHCAkKCwwNDg8QETAFBgMrZXAwPTENMAsGA1UE
ChMERHZjYTEVMBMGA1UECxMMRHZjYSBSb290IENBMRUwEwYDVQQDEwxEdmNhIFJv
b3QgQ0EwHhcNNzAwMTAxMDAwMDEwWhcNNzEwMTAxMDAwMDEwWjA5MRQwEgYDVQQK
EwtFeGFtcGxlIE9yZzELMAkGA1UECxMCSVQxFDASBgNVBAMTC2V4YW1wbGUuY29t
MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbijgcEw
gb4wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
ATAMBgNVHRMBAf8EAjAAMCkGA1UdDgQiBCCgUIN9hQcFgsz3OUsJiIR8wxLLiCWb
iUiZ9vI5zxeRpTArBgNVHSMEJDAigCCgUIN9hQcFgsz3OUsJiIR8wxLLiCWbiUiZ
9vI5zxeRpTAnBgNVHREEIDAeggtleGFtcGxlLmNvbYIPd3d3LmV4YW1wbGUuY29t
MAUGAytlcANBAL5r8t+8mofI3dx7EGlA4Z32quMzhErM2DLTw9jLIuELc0rlpeSm
NI8pbWo3Vc1AAELpci7C6g1BHk70fZpwig0=
-----END CERTIFICATE-----
`))
	expectedCert, err := x509.ParseCertificate(b.Bytes)
	r.NoError(err)
	expectedCert.Raw = nil
	expectedCert.RawTBSCertificate = nil
	expectedCert.Signature = nil
	r.NotNil(expectedCert)
	r.Equal(expectedCert, cert)
}

func TestCA_Load_InvalidPrivateKey(t *testing.T) {
	r := require.New(t)
	store := NewInMemoryStore()
	ctx := logging.WithLogger(t.Context(), slog.New(testhandler.NewTestHandler(t)))
	// Add a cert with invalid private key bytes
	cert := &x509.Certificate{SerialNumber: big.NewInt(1)}
	r.NoError(store.Add(ctx, &CertificateInfo{
		Certificate:      cert,
		Status:           CertificateStatusValid,
		CurrentCACert:    true,
		CertificateBytes: []byte{1, 2, 3},
		PrivateKeyBytes:  []byte{0, 1, 2, 3, 4, 5}, // invalid
	}))
	ca := NewCA(store)
	err := ca.Load(ctx)
	r.Error(err)
	r.NotNil(errors.GetReportableStackTrace(err))
}

type errorRand struct{}

func (e *errorRand) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestCA_newSerial_RandError(t *testing.T) {
	r := require.New(t)
	ca := NewCA(NewInMemoryStore(), WithRand(&errorRand{}))
	_, err := ca.newSerial()
	r.Error(err)
	r.NotNil(errors.GetReportableStackTrace(err))
}

type errorPubKey struct{}

func (e *errorPubKey) Public() crypto.PublicKey { return e }

func TestCA_fillSubjectKeyId_MarshalError(t *testing.T) {
	r := require.New(t)
	ca := NewCA(NewInMemoryStore())
	cert := &x509.Certificate{}
	// Use a type that will fail x509.MarshalPKIXPublicKey
	err := ca.fillSubjectKeyId(cert, &errorPubKey{})
	r.Error(err)
	r.NotNil(errors.GetReportableStackTrace(err))
}

func TestCA_SignCertificateRequest_BadSignature(t *testing.T) {
	r := require.New(t)
	store := NewInMemoryStore()
	ca := NewCA(store, WithTimeSource(func() time.Time { return time.Unix(10, 0) }))
	subject := pkix.Name{CommonName: "Test CA"}
	r.NoError(ca.Init(logging.WithLogger(t.Context(), slog.New(testhandler.NewTestHandler(t))), NewEd25519KeyGenerator(), subject))
	csr := &x509.CertificateRequest{Raw: []byte{1, 2, 3}} // invalid
	_, err := ca.SignCertificateRequest(logging.WithLogger(t.Context(), slog.New(testhandler.NewTestHandler(t))), csr)
	r.Error(err)
	r.NotNil(errors.GetReportableStackTrace(err))
}

func TestCA_SignCertificate_NotInitialized(t *testing.T) {
	r := require.New(t)
	store := NewInMemoryStore()
	ca := NewCA(store)
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "test"}}
	_, err := ca.SignCertificate(logging.WithLogger(t.Context(), slog.New(testhandler.NewTestHandler(t))), cert, nil)
	r.Error(err)
	r.NotNil(errors.GetReportableStackTrace(err))
	var notInitErr CANotInitializedError
	r.ErrorAs(err, &notInitErr)
}

func TestCA_SignCertificate_StoreAddError(t *testing.T) {
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	store := &mockStore{
		AddFunc: func(ctx context.Context, cert *CertificateInfo) error {
			// Only return error for non-CA certs
			if !cert.CurrentCACert {
				return errors.New("store add failed")
			}
			return nil
		},
	}
	ca := NewCA(store, WithTimeSource(func() time.Time { return time.Unix(10, 0) }))
	subject := pkix.Name{CommonName: "Test CA"}
	r.NoError(ca.Init(ctx, NewEd25519KeyGenerator(), subject))
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "test"}, NotBefore: ca.timeSource(), NotAfter: ca.timeSource().Add(time.Hour)}
	key, err := NewEd25519KeyGenerator().NewKey(&dummyRand{})
	r.NoError(err)
	_, err = ca.SignCertificate(ctx, cert, key.Public())
	r.ErrorContains(err, "store add failed")
	r.NotNil(errors.GetReportableStackTrace(err))
}

func TestCA_SignCertificate_StoreAddDuplicateSerial(t *testing.T) {
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	attempts := 0
	store := &mockStore{
		AddFunc: func(ctx context.Context, cert *CertificateInfo) error {
			// Only simulate duplicate serial for non-CA certs
			if !cert.CurrentCACert {
				attempts++
				if attempts < 3 {
					return DuplicateSerialError{}
				}
			}
			return nil
		},
	}
	ca := NewCA(store, WithTimeSource(func() time.Time { return time.Unix(10, 0) }))
	subject := pkix.Name{CommonName: "Test CA"}
	r.NoError(ca.Init(ctx, NewEd25519KeyGenerator(), subject))
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "test"}, NotBefore: ca.timeSource(), NotAfter: ca.timeSource().Add(time.Hour)}
	key, err := NewEd25519KeyGenerator().NewKey(&dummyRand{})
	r.NoError(err)
	_, err = ca.SignCertificate(ctx, cert, key.Public())
	r.NoError(err)
	r.Equal(3, attempts)
}

func TestCA_CheckForExpired_StoreBulkUpdateError(t *testing.T) {
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	store := &mockStore{
		BulkUpdateFunc: func(ctx context.Context, opts CertFindOptions, cb func(ctx context.Context, cert *CertificateInfo) (*CertificateInfo, error)) error {
			return errors.New("bulk update failed")
		},
	}
	ca := NewCA(store, WithTimeSource(func() time.Time { return time.Unix(10, 0) }))
	err := ca.CheckForExpired(ctx)
	r.ErrorContains(err, "bulk update failed")
	r.NotNil(errors.GetReportableStackTrace(err))
}

// mockStore implements Store and allows error injection for testing
// Only Add and BulkUpdate are implemented for these tests

type mockStore struct {
	AddFunc        func(ctx context.Context, cert *CertificateInfo) error
	BulkUpdateFunc func(ctx context.Context, opts CertFindOptions, cb func(ctx context.Context, cert *CertificateInfo) (*CertificateInfo, error)) error
}

func (m *mockStore) Find(_ context.Context, _ CertFindOptions) (*CertificateInfo, error) {
	panic("not implemented")
}
func (m *mockStore) Add(_ context.Context, cert *CertificateInfo) error {
	if m.AddFunc != nil {
		return m.AddFunc(context.Background(), cert)
	}
	return nil
}
func (m *mockStore) Update(_ context.Context, _ *CertificateInfo) error {
	panic("not implemented")
}
func (m *mockStore) Delete(_ context.Context, _ *CertificateInfo) error {
	panic("not implemented")
}
func (m *mockStore) List(_ context.Context, _ CertFindOptions, _ func(context.Context, *CertificateInfo) error) error {
	panic("not implemented")
}
func (m *mockStore) BulkUpdate(_ context.Context, _ CertFindOptions, _ func(context.Context, *CertificateInfo) (*CertificateInfo, error)) error {
	if m.BulkUpdateFunc != nil {
		return m.BulkUpdateFunc(context.Background(), CertFindOptions{}, nil)
	}
	return nil
}
