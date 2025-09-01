package dvgoca

import (
	"crypto/x509"
	"fmt"
)

type CertificateStatus int

const (
	CertificateStatusUnknown CertificateStatus = iota
	CertificateStatusValid
	CertificateStatusRevoked
	CertificateStatusExpired
)

func (s CertificateStatus) String() string {
	switch s {
	case CertificateStatusUnknown:
		return "unknown"
	case CertificateStatusValid:
		return "valid"
	case CertificateStatusRevoked:
		return "revoked"
	case CertificateStatusExpired:
		return "expired"
	default:
		return fmt.Sprintf("invalid-status(%d)", int(s))
	}
}

type CertificateInfo struct {
	Certificate   *x509.Certificate
	Status        CertificateStatus
	CurrentCACert bool
	// CertificateBytes is the DER encoded certificate.
	CertificateBytes []byte
	// PrivateKeyBytes is the private key in PKCS#8 format, it may be nil if the private key is not stored.
	PrivateKeyBytes []byte
}

// Clone creates a shallow copy of the CertificateInfo.
func (c *CertificateInfo) Clone() *CertificateInfo {
	return &CertificateInfo{
		Certificate:      c.Certificate,
		Status:           c.Status,
		CurrentCACert:    c.CurrentCACert,
		CertificateBytes: c.CertificateBytes,
		PrivateKeyBytes:  c.PrivateKeyBytes,
	}
}

func (c *CertificateInfo) PopulateFromBytes() (err error) {
	if c.Certificate != nil {
		return
	}
	if c.Certificate, err = x509.ParseCertificate(c.CertificateBytes); err != nil {
		return
	}
	return
}
