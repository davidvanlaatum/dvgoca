package dvgoca

import (
	"context"
	"math/big"
	"time"
)

type CertFindOptions struct {
	SerialNumber  *big.Int
	CurrentCACert *bool
	Status        *CertificateStatus
	NotAfterEnd   *time.Time
}

func (o *CertFindOptions) Matches(cert *CertificateInfo) bool {
	if o.SerialNumber != nil && o.SerialNumber.Cmp(cert.Certificate.SerialNumber) != 0 {
		return false
	}
	if o.CurrentCACert != nil && *o.CurrentCACert != cert.CurrentCACert {
		return false
	}
	if o.Status != nil && *o.Status != cert.Status {
		return false
	}
	if o.NotAfterEnd != nil && cert.Certificate.NotAfter.After(*o.NotAfterEnd) {
		return false
	}
	return true
}

type EndListError struct {
}

func (e EndListError) Error() string {
	return "end list"
}

type NotFoundError struct {
}

func (e NotFoundError) Error() string {
	return "not found"
}

type DuplicateSerialError struct {
}

func (e DuplicateSerialError) Error() string {
	return "duplicate serial number"
}

// Store is an interface for storing and retrieving certificates.
// Implementations must be safe for concurrent use by multiple goroutines.
type Store interface {
	// Find a single certificate matching the options. returns nil,NotFoundError if no certificate is found.
	Find(ctx context.Context, opts CertFindOptions) (*CertificateInfo, error)
	// Add a new certificate to the store. returns DuplicateSerialError if a certificate with the same serial number already exists.
	Add(ctx context.Context, cert *CertificateInfo) error
	// Update an existing certificate in the store. returns NotFoundError if the certificate does not exist.
	Update(ctx context.Context, cert *CertificateInfo) error
	// Delete an existing certificate from the store. returns NotFoundError if the certificate does not exist.
	Delete(ctx context.Context, cert *CertificateInfo) error
	// List all certificates matching the options. Call the callback for each certificate found stops if cb returns EndListError.
	List(ctx context.Context, opts CertFindOptions, cb func(ctx context.Context, cert *CertificateInfo) error) error
	BulkUpdate(ctx context.Context, opts CertFindOptions, cb func(ctx context.Context, cert *CertificateInfo) (*CertificateInfo, error)) error
}
