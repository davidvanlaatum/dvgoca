package dvgoca

import (
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCertificateInfo_Clone(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	ci := &CertificateInfo{
		Certificate:      &x509.Certificate{},
		Status:           CertificateStatusValid,
		CurrentCACert:    true,
		CertificateBytes: []byte{1, 2, 3},
		PrivateKeyBytes:  []byte{4, 5, 6},
	}
	v := reflect.ValueOf(ci).Elem()
	for i := 0; i < v.NumField(); i++ {
		t.Log("checking field is not zero", v.Type().Field(i).Name, v.Type().Field(i).Type)
		r.True(!v.Field(i).IsZero(), "field %s is zero", v.Type().Field(i).Name)
	}
	clone := ci.Clone()
	r.Equal(ci, clone)
	r.NotSame(ci, clone)
}

func TestCertificateInfo_PopulateFromBytes(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	ci := &CertificateInfo{}
	err := ci.PopulateFromBytes()
	r.ErrorContains(err, "malformed certificate")
	r.Nil(ci.Certificate)

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
-----END CERTIFICATE-----`))
	ci.CertificateBytes = b.Bytes
	err = ci.PopulateFromBytes()
	r.NoError(err)
	r.NotNil(ci.Certificate)
	saved := ci.Certificate
	err = ci.PopulateFromBytes()
	r.NoError(err)
	r.Same(saved, ci.Certificate)
}
