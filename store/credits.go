/*
FILE PATH:
    store/credits.go

DESCRIPTION:
    Mode A fiat write credit management. Atomic deduction with row-level
    locking prevents overdraft under concurrent submissions.

KEY ARCHITECTURAL DECISIONS:
    - SELECT FOR UPDATE: row lock serializes concurrent deductions for
      the same exchange. No optimistic retries — deterministic deduction.
    - Balance zero → explicit ErrInsufficientCredits (HTTP 402 upstream)
    - BulkPurchase is UPSERT: idempotent for retry safety

OVERVIEW:
    Deduct: lock row → check balance → decrement → return new balance.
    BulkPurchase: insert or increment. Balance query is read-only.

KEY DEPENDENCIES:
    - github.com/jackc/pgx/v5: row-level locking via FOR UPDATE
*/
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// -------------------------------------------------------------------------------------------------
// 1) Credit Store
// -------------------------------------------------------------------------------------------------

// ErrInsufficientCredits signals balance = 0. Upstream returns HTTP 402.
var ErrInsufficientCredits = errors.New("store/credits: insufficient credits")

// CreditStore manages Mode A write credits.
type CreditStore struct {
	db *pgxpool.Pool
}

// NewCreditStore creates a credit store.
func NewCreditStore(db *pgxpool.Pool) *CreditStore {
	return &CreditStore{db: db}
}

// Deduct atomically decrements one credit. Returns new balance.
// ErrInsufficientCredits if balance is zero. Called per-entry at admission.
func (s *CreditStore) Deduct(ctx context.Context, tx pgx.Tx, exchangeDID string) (int64, error) {
	var balance int64
	err := tx.QueryRow(ctx,
		"SELECT balance FROM credits WHERE exchange_did = $1 FOR UPDATE",
		exchangeDID,
	).Scan(&balance)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrInsufficientCredits
	}
	if err != nil {
		return 0, fmt.Errorf("store/credits: lock row: %w", err)
	}
	if balance <= 0 {
		return 0, ErrInsufficientCredits
	}

	newBalance := balance - 1
	_, err = tx.Exec(ctx,
		"UPDATE credits SET balance = $1, total_consumed = total_consumed + 1, updated_at = NOW() WHERE exchange_did = $2",
		newBalance, exchangeDID,
	)
	if err != nil {
		return 0, fmt.Errorf("store/credits: deduct: %w", err)
	}
	return newBalance, nil
}

// BulkPurchase adds credits. UPSERT for idempotent retries.
func (s *CreditStore) BulkPurchase(ctx context.Context, exchangeDID string, amount int64) (int64, error) {
	if amount <= 0 {
		return 0, fmt.Errorf("store/credits: purchase amount must be positive, got %d", amount)
	}
	var newBalance int64
	err := s.db.QueryRow(ctx, `
		INSERT INTO credits (exchange_did, balance, total_purchased, updated_at)
		VALUES ($1, $2, $2, NOW())
		ON CONFLICT (exchange_did) DO UPDATE SET
			balance = credits.balance + $2,
			total_purchased = credits.total_purchased + $2,
			updated_at = NOW()
		RETURNING balance`,
		exchangeDID, amount,
	).Scan(&newBalance)
	if err != nil {
		return 0, fmt.Errorf("store/credits: purchase: %w", err)
	}
	return newBalance, nil
}

// Balance returns the current credit balance for an exchange.
func (s *CreditStore) Balance(ctx context.Context, exchangeDID string) (int64, error) {
	var balance int64
	err := s.db.QueryRow(ctx,
		"SELECT balance FROM credits WHERE exchange_did = $1", exchangeDID,
	).Scan(&balance)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store/credits: balance: %w", err)
	}
	return balance, nil
}
