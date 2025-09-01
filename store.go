package dvgoca

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
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

type InMemoryStore struct {
	mu    sync.Mutex
	certs []*CertificateInfo
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{}
}

func (s *InMemoryStore) findSerialIndex(serialNumber *big.Int) (int, bool) {
	for i, c := range s.certs {
		if c.Certificate.SerialNumber.Cmp(serialNumber) == 0 {
			return i, true
		}
	}
	return -1, false
}

func (s *InMemoryStore) Add(_ context.Context, cert *CertificateInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, found := s.findSerialIndex(cert.Certificate.SerialNumber); found {
		return errors.WithStack(DuplicateSerialError{})
	}
	s.certs = append(s.certs, cert.Clone())
	return nil
}

func (s *InMemoryStore) Update(_ context.Context, cert *CertificateInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i, found := s.findSerialIndex(cert.Certificate.SerialNumber); found {
		s.certs[i] = cert.Clone()
		return nil
	}
	return &NotFoundError{}
}

func (s *InMemoryStore) Delete(_ context.Context, cert *CertificateInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i, found := s.findSerialIndex(cert.Certificate.SerialNumber); found {
		s.certs = append(s.certs[:i], s.certs[i+1:]...)
		return nil
	}
	return &NotFoundError{}
}

func (s *InMemoryStore) Find(ctx context.Context, opts CertFindOptions) (cert *CertificateInfo, err error) {
	if err = s.List(ctx, opts, func(ctx context.Context, c *CertificateInfo) error {
		cert = c
		return EndListError{}
	}); errors.Is(err, EndListError{}) {
		err = nil
	}
	if err == nil && cert == nil {
		err = errors.WithStack(&NotFoundError{})
	}
	return
}

func (s *InMemoryStore) List(ctx context.Context, opts CertFindOptions, cb func(ctx context.Context, cert *CertificateInfo) error) (err error) {
	for _, cert := range s.certs {
		if !opts.Matches(cert) {
			continue
		}
		if err = cb(ctx, cert.Clone()); err != nil {
			return
		}
	}
	return nil
}

func (s *InMemoryStore) BulkUpdate(ctx context.Context, opts CertFindOptions, cb func(ctx context.Context, cert *CertificateInfo) (*CertificateInfo, error)) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, cert := range s.certs {
		if !opts.Matches(cert) {
			continue
		}
		var updated *CertificateInfo
		if updated, err = cb(ctx, cert.Clone()); err != nil {
			return
		}
		if updated != nil {
			s.certs[i] = updated.Clone()
		}
	}
	return nil
}

var _ Store = (*InMemoryStore)(nil)
