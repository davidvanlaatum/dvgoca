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

// mockStore implements Store and allows error injection for testing
// Only Add, BulkUpdate, and Find are implemented for these tests
type mockStore struct {
	AddFunc        func(ctx context.Context, cert *CertificateInfo) error
	BulkUpdateFunc func(ctx context.Context, opts CertFindOptions, cb func(ctx context.Context, cert *CertificateInfo) (*CertificateInfo, error)) error
	FindFunc       func(ctx context.Context, opts CertFindOptions) (*CertificateInfo, error)
}

func (m *mockStore) Find(ctx context.Context, opts CertFindOptions) (*CertificateInfo, error) {
	if m.FindFunc != nil {
		return m.FindFunc(ctx, opts)
	}
	return nil, nil
}
func (m *mockStore) Add(ctx context.Context, cert *CertificateInfo) error {
	if m.AddFunc != nil {
		return m.AddFunc(ctx, cert)
	}
	return nil
}
func (m *mockStore) Update(_ context.Context, _ *CertificateInfo) error {
	panic("mockStore.Update called unexpectedly")
}
func (m *mockStore) Delete(_ context.Context, _ *CertificateInfo) error {
	panic("mockStore.Delete called unexpectedly")
}
func (m *mockStore) List(_ context.Context, _ CertFindOptions, _ func(context.Context, *CertificateInfo) error) error {
	panic("mockStore.List called unexpectedly")
}
func (m *mockStore) BulkUpdate(ctx context.Context, opts CertFindOptions, cb func(context.Context, *CertificateInfo) (*CertificateInfo, error)) error {
	if m.BulkUpdateFunc != nil {
		return m.BulkUpdateFunc(ctx, opts, cb)
	}
	return nil
}

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

func TestCA_CheckForExpired_EmptyStore(t *testing.T) {
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	store := NewInMemoryStore()
	ca := NewCA(store, WithTimeSource(func() time.Time { return time.Unix(10, 0) }))
	// No certs in store
	r.NoError(ca.CheckForExpired(ctx))
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

func TestCA_Init_ParseCertificateError(t *testing.T) {
	r := require.New(t)
	store := NewInMemoryStore()
	mockParse := func([]byte) (*x509.Certificate, error) {
		return nil, errors.New("parse cert fail")
	}
	ca := NewCA(store, WithCertificateParser(mockParse))
	subject := pkix.Name{CommonName: "Test CA"}
	err := ca.Init(logging.WithLogger(t.Context(), slog.New(testhandler.NewTestHandler(t))), NewEd25519KeyGenerator(), subject)
	r.ErrorContains(err, "parse cert fail")
}

func TestCA_Init_MarshalPrivateKeyError(t *testing.T) {
	r := require.New(t)
	store := NewInMemoryStore()
	mockMarshal := func(any) ([]byte, error) {
		return nil, errors.New("marshal key fail")
	}
	ca := NewCA(store, WithPrivateKeyMarshaller(mockMarshal))
	subject := pkix.Name{CommonName: "Test CA"}
	err := ca.Init(logging.WithLogger(t.Context(), slog.New(testhandler.NewTestHandler(t))), NewEd25519KeyGenerator(), subject)
	r.ErrorContains(err, "marshal key fail")
}

func TestCA_SignCertificate_ParseCertificateError(t *testing.T) {
	r := require.New(t)
	store := NewInMemoryStore()
	mockParse := func([]byte) (*x509.Certificate, error) {
		return nil, errors.New("parse cert fail")
	}
	ca := NewCA(store, WithCertificateParser(mockParse))
	ca.privateKey, _ = NewEd25519KeyGenerator().NewKey(&dummyRand{})
	ca.certificate = &x509.Certificate{Subject: pkix.Name{CommonName: "Test CA"}, SubjectKeyId: []byte{1, 2, 3}}
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	key, _ := NewEd25519KeyGenerator().NewKey(&dummyRand{})
	_, err := ca.SignCertificate(logging.WithLogger(t.Context(), slog.New(testhandler.NewTestHandler(t))), cert, key.Public())
	r.ErrorContains(err, "parse cert fail")
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

func TestCA_Init_CreateCertificateError(t *testing.T) {
	r := require.New(t)
	store := NewInMemoryStore()
	mockCreate := func(rand io.Reader, template, parent *x509.Certificate, pub, priv interface{}) ([]byte, error) {
		return nil, errors.New("create cert fail")
	}
	ca := NewCA(store, WithCertificateCreator(mockCreate))
	subject := pkix.Name{CommonName: "Test CA"}
	err := ca.Init(logging.WithLogger(t.Context(), slog.New(testhandler.NewTestHandler(t))), NewEd25519KeyGenerator(), subject)
	r.ErrorContains(err, "create cert fail")
}

func TestCA_Init_CreateCertificateReturnsInvalidBytes(t *testing.T) {
	r := require.New(t)
	store := NewInMemoryStore()
	mockCreate := func(rand io.Reader, template, parent *x509.Certificate, pub, priv interface{}) ([]byte, error) {
		return []byte{0, 1, 2, 3}, nil // not a valid cert
	}
	ca := NewCA(store, WithCertificateCreator(mockCreate))
	subject := pkix.Name{CommonName: "Test CA"}
	err := ca.Init(logging.WithLogger(t.Context(), slog.New(testhandler.NewTestHandler(t))), NewEd25519KeyGenerator(), subject)
	r.Error(err)
}

func TestCA_SignCertificate_CreateCertificateError(t *testing.T) {
	r := require.New(t)
	store := NewInMemoryStore()
	mockCreate := func(rand io.Reader, template, parent *x509.Certificate, pub, priv interface{}) ([]byte, error) {
		return nil, errors.New("create cert fail in sign")
	}
	ca := NewCA(store, WithCertificateCreator(mockCreate))
	// Set up a valid CA cert and private key
	ca.privateKey, _ = NewEd25519KeyGenerator().NewKey(&dummyRand{})
	ca.certificate = &x509.Certificate{Subject: pkix.Name{CommonName: "Test CA"}, SubjectKeyId: []byte{1, 2, 3}}
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	key, _ := NewEd25519KeyGenerator().NewKey(&dummyRand{})
	_, err := ca.SignCertificate(logging.WithLogger(t.Context(), slog.New(testhandler.NewTestHandler(t))), cert, key.Public())
	r.ErrorContains(err, "create cert fail in sign")
}

func TestCA_Load_Success(t *testing.T) {
	r := require.New(t)
	ctx := logging.WithLogger(context.Background(), slog.New(testhandler.NewTestHandler(t)))
	priv, err := NewEd25519KeyGenerator().NewKey(&dummyRand{})
	r.NoError(err)
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "Test CA"}, SerialNumber: big.NewInt(1)}
	certBytes := []byte{1, 2, 3}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	r.NoError(err)
	store := &mockStore{
		FindFunc: func(_ context.Context, _ CertFindOptions) (*CertificateInfo, error) {
			return &CertificateInfo{
				Certificate:      cert,
				CertificateBytes: certBytes,
				PrivateKeyBytes:  privBytes,
			}, nil
		},
	}
	ca := NewCA(store)
	r.NoError(ca.Load(ctx))
	r.Equal(cert, ca.certificate)
	r.NotNil(ca.privateKey)
}

func TestCA_Load_StoreError(t *testing.T) {
	r := require.New(t)
	ctx := logging.WithLogger(context.Background(), slog.New(testhandler.NewTestHandler(t)))
	store := &mockStore{
		FindFunc: func(_ context.Context, _ CertFindOptions) (*CertificateInfo, error) {
			return nil, errors.New("store error")
		},
	}
	ca := NewCA(store)
	err := ca.Load(ctx)
	r.ErrorContains(err, "store error")
}

func TestCA_Load_NoCertFound(t *testing.T) {
	r := require.New(t)
	ctx := logging.WithLogger(context.Background(), slog.New(testhandler.NewTestHandler(t)))
	store := &mockStore{
		FindFunc: func(_ context.Context, _ CertFindOptions) (*CertificateInfo, error) {
			return nil, nil
		},
	}
	ca := NewCA(store)
	err := ca.Load(ctx)
	r.ErrorContains(err, "no current CA certificate found")
}

func TestCA_Load_PrivateKeyParseError(t *testing.T) {
	r := require.New(t)
	ctx := logging.WithLogger(context.Background(), slog.New(testhandler.NewTestHandler(t)))
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "Test CA"}, SerialNumber: big.NewInt(1)}
	certBytes := []byte{1, 2, 3}
	store := &mockStore{
		FindFunc: func(_ context.Context, _ CertFindOptions) (*CertificateInfo, error) {
			return &CertificateInfo{
				Certificate:      cert,
				CertificateBytes: certBytes,
				PrivateKeyBytes:  []byte{0, 1, 2},
			}, nil
		},
	}
	ca := NewCA(store)
	err := ca.Load(ctx)
	r.ErrorContains(err, "pkcs8")
}

func TestCA_Load_PrivateKeyNotSigner(t *testing.T) {
	r := require.New(t)
	ctx := logging.WithLogger(context.Background(), slog.New(testhandler.NewTestHandler(t)))
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "Test CA"}, SerialNumber: big.NewInt(1)}
	certBytes := []byte{1, 2, 3}
	store := &mockStore{
		FindFunc: func(_ context.Context, _ CertFindOptions) (*CertificateInfo, error) {
			return &CertificateInfo{
				Certificate:      cert,
				CertificateBytes: certBytes,
				PrivateKeyBytes:  []byte("irrelevant"),
			}, nil
		},
	}
	mockParser := func(_ []byte) (any, error) {
		return []byte("not a signer"), nil
	}
	ca := NewCA(store, WithPKCS8PrivateKeyParser(mockParser))
	err := ca.Load(ctx)
	r.ErrorContains(err, "not a crypto.Signer")
}

// failKeyGen is a mock key generator that always returns an error
var errKeyGen = errors.New("keygen fail")

type failKeyGen struct{}

func (failKeyGen) NewKey(io.Reader) (crypto.Signer, error) { return nil, errKeyGen }

func TestCA_Init_KeyGenFails(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	store := &mockStore{}
	ca := NewCA(store, WithTimeSource(func() time.Time {
		return time.Unix(60, 0)
	}), WithRand(&dummyRand{}))
	subject := pkix.Name{CommonName: "fail"}
	r.ErrorIs(ca.Init(ctx, failKeyGen{}, subject), errKeyGen)
}

func TestCA_Init_StoreAddFails(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	errAdd := errors.New("add fail")
	store := &mockStore{
		AddFunc: func(ctx context.Context, cert *CertificateInfo) error {
			return errAdd
		},
	}
	ca := NewCA(store, WithTimeSource(func() time.Time {
		return time.Unix(60, 0)
	}), WithRand(&dummyRand{}))
	subject := pkix.Name{CommonName: "fail add"}
	r.ErrorIs(ca.Init(ctx, NewEd25519KeyGenerator(), subject), errAdd)
}
