package dvgoca

import (
	"context"
	"math/big"
	"sync"

	"github.com/cockroachdb/errors"
)

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

// validateCertificateInfo checks that the certificate is populated and status is valid.
func validateCertificateInfo(cert *CertificateInfo) error {
	if cert == nil || cert.Certificate == nil {
		return errors.New("certificate is nil")
	}
	switch cert.Status {
	case CertificateStatusValid, CertificateStatusRevoked, CertificateStatusExpired:
		return nil
	default:
		return errors.New("certificate status must be valid, revoked, or expired")
	}
}

func (s *InMemoryStore) Add(_ context.Context, cert *CertificateInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateCertificateInfo(cert); err != nil {
		return err
	}
	if _, found := s.findSerialIndex(cert.Certificate.SerialNumber); found {
		return errors.WithStack(DuplicateSerialError{})
	}
	s.certs = append(s.certs, cert.Clone())
	return nil
}

func (s *InMemoryStore) Update(_ context.Context, cert *CertificateInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateCertificateInfo(cert); err != nil {
		return err
	}
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
		// clone so the callback can't modify the stored cert directly
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
		// clone so the callback can't modify the stored cert directly
		if updated, err = cb(ctx, cert.Clone()); err != nil {
			return
		}
		if updated != nil {
			if err = validateCertificateInfo(updated); err != nil {
				return err
			}
			// store a clone so the caller can't modify the stored cert directly if they keep a reference
			s.certs[i] = updated.Clone()
		}
	}
	return nil
}

var _ Store = (*InMemoryStore)(nil)
