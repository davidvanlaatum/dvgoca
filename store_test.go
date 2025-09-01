package dvgoca

import (
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/davidvanlaatum/dvgoutils"
	"github.com/stretchr/testify/require"
)

func TestCertFindOptions_Matches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cert    *CertificateInfo
		opts    CertFindOptions
		matches bool
	}{
		{
			name:    "match all nil options",
			cert:    &CertificateInfo{},
			opts:    CertFindOptions{},
			matches: true,
		},
		{
			name: "match serial number",
			cert: &CertificateInfo{
				Certificate: &x509.Certificate{
					SerialNumber: big.NewInt(12345),
				},
			},
			opts: CertFindOptions{
				SerialNumber: big.NewInt(12345),
			},
			matches: true,
		},
		{
			name: "no match serial number",
			cert: &CertificateInfo{
				Certificate: &x509.Certificate{
					SerialNumber: big.NewInt(12345),
				},
			},
			opts: CertFindOptions{
				SerialNumber: big.NewInt(54321),
			},
			matches: false,
		},
		{
			name: "match current CA cert",
			cert: &CertificateInfo{
				CurrentCACert: true,
			},
			opts: CertFindOptions{
				CurrentCACert: dvgoutils.Ptr(true),
			},
			matches: true,
		},
		{
			name: "no match current CA cert",
			cert: &CertificateInfo{
				CurrentCACert: false,
			},
			opts: CertFindOptions{
				CurrentCACert: dvgoutils.Ptr(true),
			},
			matches: false,
		},
		{
			name: "match status",
			cert: &CertificateInfo{
				Status: CertificateStatusValid,
			},
			opts: CertFindOptions{
				Status: dvgoutils.Ptr(CertificateStatusValid),
			},
			matches: true,
		},
		{
			name: "no match status",
			cert: &CertificateInfo{
				Status: CertificateStatusRevoked,
			},
			opts: CertFindOptions{
				Status: dvgoutils.Ptr(CertificateStatusValid),
			},
			matches: false,
		},
		{
			name: "match NotAfterEnd",
			cert: &CertificateInfo{
				Certificate: &x509.Certificate{
					NotAfter: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			opts: CertFindOptions{
				NotAfterEnd: dvgoutils.Ptr(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
			matches: true,
		},
		{
			name: "no match NotAfterEnd",
			cert: &CertificateInfo{
				Certificate: &x509.Certificate{
					NotAfter: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			opts: CertFindOptions{
				NotAfterEnd: dvgoutils.Ptr(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
			matches: false,
		},
		{
			name: "match multiple criteria",
			cert: &CertificateInfo{
				Certificate: &x509.Certificate{
					SerialNumber: big.NewInt(12345),
					NotAfter:     time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				CurrentCACert: true,
				Status:        CertificateStatusValid,
			},
			opts: CertFindOptions{
				SerialNumber:  big.NewInt(12345),
				CurrentCACert: dvgoutils.Ptr(true),
				Status:        dvgoutils.Ptr(CertificateStatusValid),
				NotAfterEnd:   dvgoutils.Ptr(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
			matches: true,
		},
		{
			name: "no match multiple criteria",
			cert: &CertificateInfo{
				Certificate: &x509.Certificate{
					SerialNumber: big.NewInt(12345),
					NotAfter:     time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				CurrentCACert: true,
				Status:        CertificateStatusValid,
			},
			opts: CertFindOptions{
				SerialNumber:  big.NewInt(12345),
				CurrentCACert: dvgoutils.Ptr(true),
				Status:        dvgoutils.Ptr(CertificateStatusRevoked),
				NotAfterEnd:   dvgoutils.Ptr(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
			matches: false,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)
			r.Equal(test.matches, test.opts.Matches(test.cert))
		})
	}
}

func TestEndListError(t *testing.T) {
	r := require.New(t)
	endListErr := EndListError{}
	r.Equal("end list", endListErr.Error())
	var target EndListError
	r.True(errors.As(endListErr, &target))
	r.True(errors.Is(endListErr, EndListError{}))
}

func TestNotFoundError(t *testing.T) {
	r := require.New(t)
	notFoundErr := NotFoundError{}
	r.Equal("not found", notFoundErr.Error())
	var target NotFoundError
	r.True(errors.As(notFoundErr, &target))
	r.True(errors.Is(notFoundErr, NotFoundError{}))
}

func TestDuplicateSerialError(t *testing.T) {
	r := require.New(t)
	dupSerialErr := DuplicateSerialError{}
	r.Equal("duplicate serial number", dupSerialErr.Error())
	var target DuplicateSerialError
	r.True(errors.As(dupSerialErr, &target))
	r.True(errors.Is(dupSerialErr, DuplicateSerialError{}))
}
