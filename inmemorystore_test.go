package dvgoca

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"log/slog"

	"github.com/cockroachdb/errors"
	"github.com/davidvanlaatum/dvgoutils/logging"
	"github.com/davidvanlaatum/dvgoutils/logging/testhandler"
	"github.com/stretchr/testify/require"
)

func makeTestCertInfo(serial int64, notAfter time.Time, status CertificateStatus, currentCA bool) *CertificateInfo {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotAfter:     notAfter,
	}
	return &CertificateInfo{
		Certificate:   cert,
		Status:        status,
		CurrentCACert: currentCA,
	}
}

func TestInMemoryStore_Add_Duplicate(t *testing.T) {
	t.Parallel()
	s := NewInMemoryStore()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	cert := makeTestCertInfo(1, time.Now().Add(time.Hour), CertificateStatusValid, false)
	r.NoError(s.Add(ctx, cert))
	err := s.Add(ctx, cert)
	r.Error(err)
	r.True(errors.Is(err, DuplicateSerialError{}))
}

func TestInMemoryStore_Update_NotFound(t *testing.T) {
	t.Parallel()
	s := NewInMemoryStore()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	cert := makeTestCertInfo(2, time.Now().Add(time.Hour), CertificateStatusValid, false)
	err := s.Update(ctx, cert)
	r.Error(err)
	r.True(errors.Is(err, &NotFoundError{}))
}

func TestInMemoryStore_Update_Success(t *testing.T) {
	t.Parallel()
	s := NewInMemoryStore()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	cert := makeTestCertInfo(3, time.Now().Add(time.Hour), CertificateStatusValid, false)
	r.NoError(s.Add(ctx, cert))
	cert.Status = CertificateStatusRevoked
	r.NoError(s.Update(ctx, cert))
	found, err := s.Find(ctx, CertFindOptions{SerialNumber: big.NewInt(3)})
	r.NoError(err)
	r.Equal(CertificateStatusRevoked, found.Status)
}

func TestInMemoryStore_Delete_NotFound(t *testing.T) {
	t.Parallel()
	s := NewInMemoryStore()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	cert := makeTestCertInfo(4, time.Now().Add(time.Hour), CertificateStatusValid, false)
	err := s.Delete(ctx, cert)
	r.Error(err)
	r.True(errors.Is(err, &NotFoundError{}))
}

func TestInMemoryStore_Delete_Success(t *testing.T) {
	t.Parallel()
	s := NewInMemoryStore()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	cert := makeTestCertInfo(5, time.Now().Add(time.Hour), CertificateStatusValid, false)
	r.NoError(s.Add(ctx, cert))
	r.NoError(s.Delete(ctx, cert))
	_, err := s.Find(ctx, CertFindOptions{SerialNumber: big.NewInt(5)})
	r.Error(err)
	r.True(errors.Is(err, &NotFoundError{}))
}

func TestInMemoryStore_Find(t *testing.T) {
	t.Parallel()
	s := NewInMemoryStore()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	cert := makeTestCertInfo(6, time.Now().Add(time.Hour), CertificateStatusValid, true)
	r.NoError(s.Add(ctx, cert))
	found, err := s.Find(ctx, CertFindOptions{SerialNumber: big.NewInt(6)})
	r.NoError(err)
	r.NotNil(found)
	r.Equal(cert.Certificate.SerialNumber, found.Certificate.SerialNumber)
	_, err = s.Find(ctx, CertFindOptions{SerialNumber: big.NewInt(999)})
	r.Error(err)
	r.True(errors.Is(err, &NotFoundError{}))
}

func TestInMemoryStore_List(t *testing.T) {
	t.Parallel()
	s := NewInMemoryStore()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	now := time.Now()
	_ = s.Add(ctx, makeTestCertInfo(7, now.Add(time.Hour), CertificateStatusValid, false))
	_ = s.Add(ctx, makeTestCertInfo(8, now.Add(2*time.Hour), CertificateStatusRevoked, true))
	count := 0
	err := s.List(ctx, CertFindOptions{}, func(ctx context.Context, cert *CertificateInfo) error {
		count++
		return nil
	})
	r.NoError(err)
	r.Equal(2, count)
	// Filter by CurrentCACert
	count = 0
	ca := true
	err = s.List(ctx, CertFindOptions{CurrentCACert: &ca}, func(ctx context.Context, cert *CertificateInfo) error {
		count++
		return nil
	})
	r.NoError(err)
	r.Equal(1, count)
}

func TestInMemoryStore_BulkUpdate(t *testing.T) {
	t.Parallel()
	s := NewInMemoryStore()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	now := time.Now()
	_ = s.Add(ctx, makeTestCertInfo(9, now.Add(time.Hour), CertificateStatusValid, false))
	_ = s.Add(ctx, makeTestCertInfo(10, now.Add(2*time.Hour), CertificateStatusValid, false))
	status := CertificateStatusRevoked
	r.NoError(s.BulkUpdate(ctx, CertFindOptions{}, func(ctx context.Context, cert *CertificateInfo) (*CertificateInfo, error) {
		cert.Status = status
		return cert, nil
	}))
	count := 0
	err := s.List(ctx, CertFindOptions{Status: &status}, func(ctx context.Context, cert *CertificateInfo) error {
		count++
		return nil
	})
	r.NoError(err)
	r.Equal(2, count)
}

func TestInMemoryStore_BulkUpdate_CallbackError(t *testing.T) {
	t.Parallel()
	s := NewInMemoryStore()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	now := time.Now()
	_ = s.Add(ctx, makeTestCertInfo(20, now.Add(time.Hour), CertificateStatusValid, false))
	_ = s.Add(ctx, makeTestCertInfo(21, now.Add(2*time.Hour), CertificateStatusValid, false))
	testErr := errors.New("callback error")
	updateCount := 0
	err := s.BulkUpdate(ctx, CertFindOptions{}, func(ctx context.Context, cert *CertificateInfo) (*CertificateInfo, error) {
		updateCount++
		return nil, testErr
	})
	r.ErrorIs(err, testErr)
	r.Equal(1, updateCount, "callback should be called only once before error is returned")

	// Ensure no certificates were updated
	status := CertificateStatusRevoked
	count := 0
	err = s.List(ctx, CertFindOptions{Status: &status}, func(ctx context.Context, cert *CertificateInfo) error {
		count++
		return nil
	})
	r.NoError(err)
	r.Equal(0, count, "no certificates should be updated to revoked")
}

func TestInMemoryStore_BulkUpdate_CallbackReturnsNil(t *testing.T) {
	t.Parallel()
	s := NewInMemoryStore()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	now := time.Now()
	cert := makeTestCertInfo(30, now.Add(time.Hour), CertificateStatusValid, false)
	r.NoError(s.Add(ctx, cert))
	// Callback mutates the cert but returns nil
	err := s.BulkUpdate(ctx, CertFindOptions{}, func(ctx context.Context, c *CertificateInfo) (*CertificateInfo, error) {
		c.Status = CertificateStatusRevoked
		return nil, nil
	})
	r.NoError(err)
	// The cert in the store should remain unchanged
	found, err := s.Find(ctx, CertFindOptions{SerialNumber: big.NewInt(30)})
	r.NoError(err)
	r.Equal(CertificateStatusValid, found.Status, "cert in store should not be updated if callback returns nil")
}

func TestInMemoryStore_BulkUpdate_CallbackReturnedCertMutation(t *testing.T) {
	t.Parallel()
	s := NewInMemoryStore()
	r := require.New(t)
	l := slog.New(testhandler.NewTestHandler(t))
	ctx := logging.WithLogger(t.Context(), l)
	now := time.Now()
	cert := makeTestCertInfo(40, now.Add(time.Hour), CertificateStatusValid, false)
	r.NoError(s.Add(ctx, cert))
	var kept *CertificateInfo
	// BulkUpdate returns a new cert, keeps a reference to it
	err := s.BulkUpdate(ctx, CertFindOptions{}, func(ctx context.Context, c *CertificateInfo) (*CertificateInfo, error) {
		updated := c.Clone()
		updated.Status = CertificateStatusRevoked
		kept = updated
		return updated, nil
	})
	r.NoError(err)
	// Mutate the kept cert after BulkUpdate
	kept.Status = CertificateStatusValid
	// The cert in the store should remain revoked
	found, err := s.Find(ctx, CertFindOptions{SerialNumber: big.NewInt(40)})
	r.NoError(err)
	r.Equal(CertificateStatusRevoked, found.Status, "store should not be affected by external mutation of returned cert")
}

func TestInMemoryStore_Add_Validation(t *testing.T) {
	s := NewInMemoryStore()
	r := require.New(t)
	ctx := context.Background()

	// Nil Certificate
	invalidCert := &CertificateInfo{
		Certificate: nil,
		Status:      CertificateStatusValid,
	}
	err := s.Add(ctx, invalidCert)
	r.Error(err)
	r.Contains(err.Error(), "certificate is nil")

	// Invalid Status
	cert := makeTestCertInfo(200, time.Now().Add(time.Hour), CertificateStatusUnknown, false)
	err = s.Add(ctx, cert)
	r.Error(err)
	r.Contains(err.Error(), "certificate status must be valid, revoked, or expired")
}

func TestInMemoryStore_Update_Validation(t *testing.T) {
	s := NewInMemoryStore()
	r := require.New(t)
	ctx := context.Background()

	// Add a valid cert first
	cert := makeTestCertInfo(201, time.Now().Add(time.Hour), CertificateStatusValid, false)
	r.NoError(s.Add(ctx, cert))

	// Nil Certificate
	invalidCert := &CertificateInfo{
		Certificate: nil,
		Status:      CertificateStatusValid,
	}
	invalidCert.Certificate = nil
	invalidCert.Status = CertificateStatusValid
	invalidCert.CertificateBytes = nil
	err := s.Update(ctx, invalidCert)
	r.Error(err)
	r.Contains(err.Error(), "certificate is nil")

	// Invalid Status
	cert.Status = CertificateStatusUnknown
	err = s.Update(ctx, cert)
	r.Error(err)
	r.Contains(err.Error(), "certificate status must be valid, revoked, or expired")
}

func TestInMemoryStore_BulkUpdate_Validation(t *testing.T) {
	s := NewInMemoryStore()
	r := require.New(t)
	ctx := context.Background()

	cert := makeTestCertInfo(202, time.Now().Add(time.Hour), CertificateStatusValid, false)
	r.NoError(s.Add(ctx, cert))

	// Callback returns cert with nil Certificate
	err := s.BulkUpdate(ctx, CertFindOptions{SerialNumber: big.NewInt(202)}, func(ctx context.Context, c *CertificateInfo) (*CertificateInfo, error) {
		c.Certificate = nil
		return c, nil
	})
	r.Error(err)
	r.Contains(err.Error(), "certificate is nil")

	// Callback returns cert with invalid Status
	err = s.BulkUpdate(ctx, CertFindOptions{SerialNumber: big.NewInt(202)}, func(ctx context.Context, c *CertificateInfo) (*CertificateInfo, error) {
		c.Certificate = &x509.Certificate{SerialNumber: big.NewInt(202)}
		c.Status = CertificateStatusUnknown
		return c, nil
	})
	r.Error(err)
	r.Contains(err.Error(), "certificate status must be valid, revoked, or expired")
}
