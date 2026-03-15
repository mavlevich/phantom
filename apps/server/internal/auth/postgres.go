package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type postgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) Repository {
	return &postgresRepository{db: db}
}

func (r *postgresRepository) FindUserByUsername(ctx context.Context, username string) (*User, error) {
	const query = `
		SELECT id, username, password_hash, public_key, created_at, updated_at
		FROM users
		WHERE username = $1
	`

	var (
		id        string
		user      User
		createdAt time.Time
		updatedAt time.Time
	)

	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&id,
		&user.Username,
		&user.PasswordHash,
		&user.PublicKey,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("query user by username: %w", err)
	}

	userID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("parse user id: %w", err)
	}

	user.ID = userID
	user.CreatedAt = createdAt
	user.UpdatedAt = updatedAt

	return &user, nil
}

func (r *postgresRepository) FindUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	const query = `
		SELECT id, username, password_hash, public_key, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	var (
		rawID     string
		user      User
		createdAt time.Time
		updatedAt time.Time
	)

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&rawID,
		&user.Username,
		&user.PasswordHash,
		&user.PublicKey,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("query user by id: %w", err)
	}

	userID, err := uuid.Parse(rawID)
	if err != nil {
		return nil, fmt.Errorf("parse user id: %w", err)
	}

	user.ID = userID
	user.CreatedAt = createdAt
	user.UpdatedAt = updatedAt

	return &user, nil
}

func (r *postgresRepository) FindInviteByCode(ctx context.Context, code string) (*Invite, error) {
	const query = `
		SELECT code, created_by, created_at, expires_at, used_at, used_by_user_id
		FROM invites
		WHERE code = $1
	`

	invite, err := scanInvite(r.db.QueryRowContext(ctx, query, code))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInviteNotFound
		}
		return nil, fmt.Errorf("query invite by code: %w", err)
	}

	return invite, nil
}

func (r *postgresRepository) CreateUserFromInvite(ctx context.Context, user *User, inviteCode string, usedAt time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	invite, err := findInviteForUpdate(ctx, tx, inviteCode)
	if err != nil {
		return err
	}

	if invite.UsedAt != nil {
		return ErrInviteAlreadyUsed
	}
	if invite.ExpiresAt != nil && !invite.ExpiresAt.After(usedAt) {
		return ErrInviteExpired
	}

	const insertUser = `
		INSERT INTO users (id, username, password_hash, public_key, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err = tx.ExecContext(
		ctx,
		insertUser,
		user.ID,
		user.Username,
		user.PasswordHash,
		user.PublicKey,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrUserAlreadyExists
		}
		return fmt.Errorf("insert user: %w", err)
	}

	const updateInvite = `
		UPDATE invites
		SET used_at = $2, used_by_user_id = $3
		WHERE code = $1
	`

	if _, err := tx.ExecContext(ctx, updateInvite, inviteCode, usedAt, user.ID); err != nil {
		return fmt.Errorf("mark invite as used: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit register tx: %w", err)
	}

	return nil
}

func findInviteForUpdate(ctx context.Context, tx *sql.Tx, code string) (*Invite, error) {
	const query = `
		SELECT code, created_by, created_at, expires_at, used_at, used_by_user_id
		FROM invites
		WHERE code = $1
		FOR UPDATE
	`

	invite, err := scanInvite(tx.QueryRowContext(ctx, query, code))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInviteNotFound
		}
		return nil, fmt.Errorf("query invite for update: %w", err)
	}

	return invite, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

type scanner interface {
	Scan(dest ...any) error
}

func scanInvite(row scanner) (*Invite, error) {
	var (
		invite          Invite
		expiresAt       sql.NullTime
		usedAt          sql.NullTime
		usedByUserIDRaw sql.NullString
	)

	if err := row.Scan(
		&invite.Code,
		&invite.CreatedBy,
		&invite.CreatedAt,
		&expiresAt,
		&usedAt,
		&usedByUserIDRaw,
	); err != nil {
		return nil, err
	}

	if expiresAt.Valid {
		invite.ExpiresAt = &expiresAt.Time
	}
	if usedAt.Valid {
		invite.UsedAt = &usedAt.Time
	}
	if usedByUserIDRaw.Valid {
		usedByUserID, err := uuid.Parse(usedByUserIDRaw.String)
		if err != nil {
			return nil, fmt.Errorf("parse invite used_by_user_id: %w", err)
		}
		invite.UsedByUserID = &usedByUserID
	}

	return &invite, nil
}
