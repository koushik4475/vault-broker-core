package tests

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ER-brocode/vault-broker-core/pkg/lease"
	"github.com/ER-brocode/vault-broker-core/pkg/provider"
)

func TestLeaseExpirationAndAutoReaper(t *testing.T) {
	mgr := lease.NewManager(10 * time.Millisecond)
	defer mgr.Stop()

	var revokedCount int32
	mockRevoke := func(ctx context.Context, l *lease.Lease) error {
		atomic.AddInt32(&revokedCount, 1)
		return nil
	}

	// Create lease with 50ms TTL
	l, err := mgr.CreateLease("DB_TEMP_CRED", "spiffe://prod/billing", map[string]string{"user": "alice"}, 50*time.Millisecond, 200*time.Millisecond, mockRevoke, nil)
	if err != nil {
		t.Fatalf("failed to create lease: %v", err)
	}

	if l.State != lease.StateActive {
		t.Fatalf("expected state ACTIVE, got %s", l.State)
	}

	// Wait for reaper to sweep expired lease
	time.Sleep(120 * time.Millisecond)

	fetched, err := mgr.GetLease(l.ID)
	if err != nil {
		t.Fatalf("failed to retrieve lease: %v", err)
	}

	if fetched.State != lease.StateRevoked {
		t.Fatalf("expected state REVOKED after reaper run, got %s", fetched.State)
	}

	if atomic.LoadInt32(&revokedCount) != 1 {
		t.Fatalf("expected revoke callback to be called once, got %d", atomic.LoadInt32(&revokedCount))
	}
}

func TestManualLeaseRevocation(t *testing.T) {
	mgr := lease.NewManager(100 * time.Millisecond)
	defer mgr.Stop()

	var revokedCalled bool
	mockRevoke := func(ctx context.Context, l *lease.Lease) error {
		revokedCalled = true
		return nil
	}

	l, err := mgr.CreateLease("AWS_IAM", "spiffe://prod/api-gateway", map[string]string{"role": "arn:aws:iam::123:role/ApiRole"}, 5*time.Second, 10*time.Second, mockRevoke, nil)
	if err != nil {
		t.Fatalf("failed to create lease: %v", err)
	}

	ctx := context.Background()
	err = mgr.RevokeLease(ctx, l.ID)
	if err != nil {
		t.Fatalf("failed to revoke lease: %v", err)
	}

	if !revokedCalled {
		t.Fatal("expected revoke callback to be executed")
	}

	fetched, _ := mgr.GetLease(l.ID)
	if fetched.State != lease.StateRevoked {
		t.Fatalf("expected state REVOKED, got %s", fetched.State)
	}
}

func TestAutoRotationDaemonLifecycle(t *testing.T) {
	mgr := lease.NewManager(50 * time.Millisecond)
	defer mgr.Stop()

	daemon := lease.NewAutoRotationDaemon(mgr, 0.40, 20*time.Millisecond) // Rotate when 40% TTL remaining
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	daemon.Start(ctx)
	defer daemon.Stop()

	var rotatedCount int32
	rotateFn := func(ctx context.Context, l *lease.Lease) error {
		atomic.AddInt32(&rotatedCount, 1)
		// Extend lease upon rotation
		l.ExpiresAt = time.Now().UTC().Add(500 * time.Millisecond)
		return nil
	}

	// 100ms TTL. At 40ms remaining (i.e. after 60ms), rotation should trigger
	l, err := mgr.CreateLease("GCP_SA", "spiffe://prod/worker", map[string]string{"sa": "sa-worker@proj.iam.gserviceaccount.com"}, 100*time.Millisecond, 2*time.Second, nil, rotateFn)
	if err != nil {
		t.Fatalf("failed to create lease: %v", err)
	}

	time.Sleep(80 * time.Millisecond)

	if atomic.LoadInt32(&rotatedCount) < 1 {
		t.Fatalf("expected auto-rotation to trigger, got %d rotations", atomic.LoadInt32(&rotatedCount))
	}

	_ = l
}

func TestProvidersE2E(t *testing.T) {
	ctx := context.Background()
	mgr := lease.NewManager(100 * time.Millisecond)
	defer mgr.Stop()

	// 1. AWS IAM Provider
	awsMock := provider.NewMockAWSSTSClient()
	awsProv := provider.NewAWSIAMProvider(awsMock)

	awsCreds, awsRevoke, awsRotate, err := awsProv.Generate(ctx, provider.Request{
		Identity:    "spiffe://prod/orders-service",
		RoleOrScope: "arn:aws:iam::123456789012:role/OrderProcessorRole",
		TTL:         10 * time.Minute,
		MaxTTL:      1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to generate AWS creds: %v", err)
	}

	lAWS, err := mgr.CreateLease(string(awsProv.Type()), "spiffe://prod/orders-service", awsCreds.Attributes, awsCreds.TTL, awsCreds.MaxTTL, awsRevoke, awsRotate)
	if err != nil {
		t.Fatalf("failed to track AWS lease: %v", err)
	}

	// Revoke AWS Lease
	err = mgr.RevokeLease(ctx, lAWS.ID)
	if err != nil {
		t.Fatalf("failed to revoke AWS lease: %v", err)
	}
	if !awsMock.RevokedSessions[lAWS.Data["AWS_ROLE_ARN"]+"/"+lAWS.Data["AWS_SESSION_NAME"]] {
		t.Fatal("expected AWS STS session to be revoked in client")
	}

	// 2. Database Provider
	dbMock := provider.NewMockDatabaseExecutor()
	dbProv := provider.NewDatabaseProvider(provider.TypePostgres, "postgres.internal", 5432, "appdb", dbMock)

	dbCreds, dbRevoke, dbRotate, err := dbProv.Generate(ctx, provider.Request{
		Identity:    "spiffe://prod/analytics",
		RoleOrScope: "readonly_analyst",
		TTL:         15 * time.Minute,
		MaxTTL:      2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to generate DB creds: %v", err)
	}

	username := dbCreds.Attributes["DB_USERNAME"]
	if !dbMock.CheckUserExists(ctx, username) {
		t.Fatal("expected dynamic database user to exist in executor")
	}

	lDB, err := mgr.CreateLease(string(dbProv.Type()), "spiffe://prod/analytics", dbCreds.Attributes, dbCreds.TTL, dbCreds.MaxTTL, dbRevoke, dbRotate)
	if err != nil {
		t.Fatalf("failed to create DB lease: %v", err)
	}

	err = mgr.RevokeLease(ctx, lDB.ID)
	if err != nil {
		t.Fatalf("failed to revoke DB lease: %v", err)
	}

	if dbMock.CheckUserExists(ctx, username) {
		t.Fatal("expected dynamic database user to be dropped upon lease revocation")
	}
}


func TestLeaseManagerStopIsIdempotent(t *testing.T) {
	mgr := lease.NewManager(time.Hour)

	mgr.Stop()
	mgr.Stop()
}
