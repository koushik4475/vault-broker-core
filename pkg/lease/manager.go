package lease

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrLeaseNotFound = errors.New("lease not found or already terminated")
	ErrLeaseExpired  = errors.New("lease has expired and cannot be renewed")
	ErrMaxTTLReached = errors.New("lease renewal exceeds maximum allowable TTL")
	ErrRevocationErr = errors.New("error executing lease revocation callback")
)

// State represents the lifecycle stage of a dynamic credential lease.
type State string

const (
	StateActive  State = "ACTIVE"
	StateRenewed State = "RENEWED"
	StateExpired State = "EXPIRED"
	StateRevoked State = "REVOKED"
)

// RevokeFunc is the provider-specific callback executed to destroy credentials upstream.
type RevokeFunc func(ctx context.Context, lease *Lease) error

// RotateFunc is the provider-specific callback executed when automatic rotation is triggered.
type RotateFunc func(ctx context.Context, lease *Lease) error

// Lease encapsulates the state, timing, and metadata for an ephemeral secret or credential.
type Lease struct {
	ID           string            `json:"id"`
	SecretType   string            `json:"secret_type"`
	IssuedTo     string            `json:"issued_to"`
	Data         map[string]string `json:"data"`
	State        State             `json:"state"`
	CreatedAt    time.Time         `json:"created_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
	LastRenewed  time.Time         `json:"last_renewed"`
	InitialTTL   time.Duration     `json:"initial_ttl"`
	MaxTTL       time.Duration     `json:"max_ttl"`
	RenewCount   int               `json:"renew_count"`
	RevokeOnTerm bool              `json:"revoke_on_term"`

	revokeFunc RevokeFunc `json:"-"`
	rotateFunc RotateFunc `json:"-"`
}

// Manager maintains dynamic leases, processes expirations, and coordinates revocations.
type Manager struct {
	mu            sync.RWMutex
	leases        map[string]*Lease
	stopCh        chan struct{}
	stopOnce      sync.Once
	cleanupTicker *time.Ticker
	onRevokeHook  func(l *Lease)
}

// NewManager initializes the dynamic lease lifecycle manager.
func NewManager(cleanupInterval time.Duration) *Manager {
	if cleanupInterval <= 0 {
		cleanupInterval = 100 * time.Millisecond
	}

	mgr := &Manager{
		leases:        make(map[string]*Lease),
		stopCh:        make(chan struct{}),
		cleanupTicker: time.NewTicker(cleanupInterval),
	}

	go mgr.reaperLoop()
	return mgr
}

// SetOnRevokeHook registers an event hook triggered after successful revocations.
func (m *Manager) SetOnRevokeHook(fn func(l *Lease)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onRevokeHook = fn
}

// CreateLease allocates a new tracked lease with defined TTL constraints and callbacks.
func (m *Manager) CreateLease(secretType, issuedTo string, data map[string]string, ttl, maxTTL time.Duration, revoke RevokeFunc, rotate RotateFunc) (*Lease, error) {
	if ttl <= 0 {
		return nil, errors.New("TTL must be greater than zero")
	}
	if maxTTL < ttl {
		maxTTL = ttl
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random lease ID: %w", err)
	}
	leaseID := "lease_" + hex.EncodeToString(idBytes)

	now := time.Now().UTC()
	l := &Lease{
		ID:           leaseID,
		SecretType:   secretType,
		IssuedTo:     issuedTo,
		Data:         data,
		State:        StateActive,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		LastRenewed:  now,
		InitialTTL:   ttl,
		MaxTTL:       maxTTL,
		RenewCount:   0,
		RevokeOnTerm: true,
		revokeFunc:   revoke,
		rotateFunc:   rotate,
	}

	m.mu.Lock()
	m.leases[leaseID] = l
	m.mu.Unlock()

	return l, nil
}

// GetLease retrieves an active or tracked lease by ID.
func (m *Manager) GetLease(leaseID string) (*Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	l, exists := m.leases[leaseID]
	if !exists {
		return nil, ErrLeaseNotFound
	}
	return l, nil
}

// RenewLease extends the validity period of an active lease within maxTTL boundaries.
func (m *Manager) RenewLease(leaseID string, extendTTL time.Duration) (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, exists := m.leases[leaseID]
	if !exists {
		return nil, ErrLeaseNotFound
	}

	now := time.Now().UTC()
	if l.State != StateActive && l.State != StateRenewed {
		return nil, ErrLeaseExpired
	}

	if now.After(l.ExpiresAt) {
		l.State = StateExpired
		return nil, ErrLeaseExpired
	}

	newExpiry := l.ExpiresAt.Add(extendTTL)
	maxExpiry := l.CreatedAt.Add(l.MaxTTL)

	if newExpiry.After(maxExpiry) {
		return nil, ErrMaxTTLReached
	}

	l.ExpiresAt = newExpiry
	l.LastRenewed = now
	l.RenewCount++
	l.State = StateRenewed

	return l, nil
}

// RevokeLease immediately revokes the lease and invokes the provider revocation routine.
func (m *Manager) RevokeLease(ctx context.Context, leaseID string) error {
	m.mu.Lock()
	l, exists := m.leases[leaseID]
	if !exists {
		m.mu.Unlock()
		return ErrLeaseNotFound
	}
	if l.State == StateRevoked {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	// Execute revocation callback outside lock
	if l.revokeFunc != nil {
		if err := l.revokeFunc(ctx, l); err != nil {
			return fmt.Errorf("%w: %v", ErrRevocationErr, err)
		}
	}

	m.mu.Lock()
	l.State = StateRevoked
	hook := m.onRevokeHook
	m.mu.Unlock()

	if hook != nil {
		hook(l)
	}

	return nil
}

// reaperLoop continuously checks for expired leases and triggers cleanups.
func (m *Manager) reaperLoop() {
	for {
		select {
		case <-m.stopCh:
			return
		case <-m.cleanupTicker.C:
			m.sweepExpired()
		}
	}
}

func (m *Manager) sweepExpired() {
	m.mu.Lock()
	var toRevoke []*Lease
	now := time.Now().UTC()

	for _, l := range m.leases {
		if (l.State == StateActive || l.State == StateRenewed) && now.After(l.ExpiresAt) {
			l.State = StateExpired
			toRevoke = append(toRevoke, l)
		}
	}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, l := range toRevoke {
		if l.revokeFunc != nil {
			_ = l.revokeFunc(ctx, l)
		}
		m.mu.Lock()
		l.State = StateRevoked
		hook := m.onRevokeHook
		m.mu.Unlock()
		if hook != nil {
			hook(l)
		}
	}
}

// Stop gracefully shuts down the lease manager reaper.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		m.cleanupTicker.Stop()
		close(m.stopCh)
	})
}

// ActiveCount returns number of currently active or renewed leases.
func (m *Manager) ActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, l := range m.leases {
		if l.State == StateActive || l.State == StateRenewed {
			count++
		}
	}
	return count
}
