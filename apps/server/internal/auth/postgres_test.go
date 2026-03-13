package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNewService(t *testing.T) {
	repo := &registerRepoStub{}

	svc := NewService(repo)
	if svc == nil {
		t.Fatal("NewService() = nil, want service")
	}
}

func TestNewPostgresRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	if repo == nil {
		t.Fatal("NewPostgresRepository() = nil, want repository")
	}
	if _, ok := repo.(*postgresRepository); !ok {
		t.Fatalf("NewPostgresRepository() type = %T, want *postgresRepository", repo)
	}
}

func TestFindUserByUsernameSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := &postgresRepository{db: db}
	userID := uuid.New()
	createdAt := time.Now().UTC().Round(time.Second)
	updatedAt := createdAt.Add(time.Minute)

	rows := sqlmock.NewRows([]string{"id", "username", "password_hash", "public_key", "created_at", "updated_at"}).
		AddRow(userID.String(), "alice123", "hashed", "public-key", createdAt, updatedAt)

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT id, username, password_hash, public_key, created_at, updated_at
		FROM users
		WHERE username = $1
	`)).
		WithArgs("alice123").
		WillReturnRows(rows)

	user, err := repo.FindUserByUsername(context.Background(), "alice123")
	if err != nil {
		t.Fatalf("FindUserByUsername() error = %v", err)
	}
	if user == nil {
		t.Fatal("FindUserByUsername() = nil, want user")
	}
	if user.ID != userID {
		t.Fatalf("user.ID = %v, want %v", user.ID, userID)
	}
	if user.Username != "alice123" {
		t.Fatalf("user.Username = %q, want alice123", user.Username)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("mock expectations: %v", err)
	}
}

func TestFindUserByUsernameNoRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := &postgresRepository{db: db}

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT id, username, password_hash, public_key, created_at, updated_at
		FROM users
		WHERE username = $1
	`)).
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)

	user, err := repo.FindUserByUsername(context.Background(), "missing")
	if err != nil {
		t.Fatalf("FindUserByUsername() error = %v", err)
	}
	if user != nil {
		t.Fatalf("FindUserByUsername() = %v, want nil", user)
	}
}

func TestFindUserByUsernameRejectsInvalidUUID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := &postgresRepository{db: db}
	rows := sqlmock.NewRows([]string{"id", "username", "password_hash", "public_key", "created_at", "updated_at"}).
		AddRow("not-a-uuid", "alice123", "hashed", "public-key", time.Now().UTC(), time.Now().UTC())

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT id, username, password_hash, public_key, created_at, updated_at
		FROM users
		WHERE username = $1
	`)).
		WithArgs("alice123").
		WillReturnRows(rows)

	_, err = repo.FindUserByUsername(context.Background(), "alice123")
	if err == nil {
		t.Fatal("FindUserByUsername() error = nil, want parse error")
	}
}

func TestFindInviteByCodeSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := &postgresRepository{db: db}
	now := time.Now().UTC().Round(time.Second)
	expiresAt := now.Add(time.Hour)
	usedBy := uuid.New()

	rows := sqlmock.NewRows([]string{"code", "created_by", "created_at", "expires_at", "used_at", "used_by_user_id"}).
		AddRow("ALPHA-INVITE-001", "admin", now, expiresAt, now, usedBy.String())

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT code, created_by, created_at, expires_at, used_at, used_by_user_id
		FROM invites
		WHERE code = $1
	`)).
		WithArgs("ALPHA-INVITE-001").
		WillReturnRows(rows)

	invite, err := repo.FindInviteByCode(context.Background(), "ALPHA-INVITE-001")
	if err != nil {
		t.Fatalf("FindInviteByCode() error = %v", err)
	}
	if invite == nil {
		t.Fatal("FindInviteByCode() = nil, want invite")
	}
	if invite.Code != "ALPHA-INVITE-001" {
		t.Fatalf("invite.Code = %q, want ALPHA-INVITE-001", invite.Code)
	}
	if invite.UsedByUserID == nil || *invite.UsedByUserID != usedBy {
		t.Fatalf("invite.UsedByUserID = %v, want %v", invite.UsedByUserID, usedBy)
	}
}

func TestFindInviteByCodeNoRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := &postgresRepository{db: db}

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT code, created_by, created_at, expires_at, used_at, used_by_user_id
		FROM invites
		WHERE code = $1
	`)).
		WithArgs("UNKNOWN").
		WillReturnError(sql.ErrNoRows)

	_, err = repo.FindInviteByCode(context.Background(), "UNKNOWN")
	if !errors.Is(err, ErrInviteNotFound) {
		t.Fatalf("FindInviteByCode() error = %v, want %v", err, ErrInviteNotFound)
	}
}

func TestFindInviteByCodeRejectsInvalidUsedByUUID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := &postgresRepository{db: db}
	rows := sqlmock.NewRows([]string{"code", "created_by", "created_at", "expires_at", "used_at", "used_by_user_id"}).
		AddRow("ALPHA-INVITE-001", "admin", time.Now().UTC(), nil, nil, "not-a-uuid")

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT code, created_by, created_at, expires_at, used_at, used_by_user_id
		FROM invites
		WHERE code = $1
	`)).
		WithArgs("ALPHA-INVITE-001").
		WillReturnRows(rows)

	_, err = repo.FindInviteByCode(context.Background(), "ALPHA-INVITE-001")
	if err == nil {
		t.Fatal("FindInviteByCode() error = nil, want parse error")
	}
}

func TestCreateUserFromInviteSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := &postgresRepository{db: db}
	now := time.Now().UTC().Round(time.Second)
	user := &User{
		ID:           uuid.New(),
		Username:     "alice123",
		PasswordHash: "hashed",
		PublicKey:    "public-key",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT code, created_by, created_at, expires_at, used_at, used_by_user_id
		FROM invites
		WHERE code = $1
		FOR UPDATE
	`)).
		WithArgs("ALPHA-INVITE-001").
		WillReturnRows(sqlmock.NewRows([]string{"code", "created_by", "created_at", "expires_at", "used_at", "used_by_user_id"}).
			AddRow("ALPHA-INVITE-001", "admin", now.Add(-time.Hour), now.Add(time.Hour), nil, nil))
	mock.ExpectExec(regexp.QuoteMeta(`
		INSERT INTO users (id, username, password_hash, public_key, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`)).
		WithArgs(user.ID, user.Username, user.PasswordHash, user.PublicKey, user.CreatedAt, user.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(regexp.QuoteMeta(`
		UPDATE invites
		SET used_at = $2, used_by_user_id = $3
		WHERE code = $1
	`)).
		WithArgs("ALPHA-INVITE-001", now, user.ID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = repo.CreateUserFromInvite(context.Background(), user, "ALPHA-INVITE-001", now)
	if err != nil {
		t.Fatalf("CreateUserFromInvite() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("mock expectations: %v", err)
	}
}

func TestCreateUserFromInviteRejectsUsedInvite(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := &postgresRepository{db: db}
	now := time.Now().UTC().Round(time.Second)
	usedAt := now.Add(-time.Minute)

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT code, created_by, created_at, expires_at, used_at, used_by_user_id
		FROM invites
		WHERE code = $1
		FOR UPDATE
	`)).
		WithArgs("ALPHA-INVITE-001").
		WillReturnRows(sqlmock.NewRows([]string{"code", "created_by", "created_at", "expires_at", "used_at", "used_by_user_id"}).
			AddRow("ALPHA-INVITE-001", "admin", now.Add(-time.Hour), nil, usedAt, nil))
	mock.ExpectRollback()

	err = repo.CreateUserFromInvite(context.Background(), &User{}, "ALPHA-INVITE-001", now)
	if !errors.Is(err, ErrInviteAlreadyUsed) {
		t.Fatalf("CreateUserFromInvite() error = %v, want %v", err, ErrInviteAlreadyUsed)
	}
}

func TestCreateUserFromInviteRejectsExpiredInvite(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := &postgresRepository{db: db}
	now := time.Now().UTC().Round(time.Second)

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT code, created_by, created_at, expires_at, used_at, used_by_user_id
		FROM invites
		WHERE code = $1
		FOR UPDATE
	`)).
		WithArgs("ALPHA-INVITE-001").
		WillReturnRows(sqlmock.NewRows([]string{"code", "created_by", "created_at", "expires_at", "used_at", "used_by_user_id"}).
			AddRow("ALPHA-INVITE-001", "admin", now.Add(-time.Hour), now, nil, nil))
	mock.ExpectRollback()

	err = repo.CreateUserFromInvite(context.Background(), &User{}, "ALPHA-INVITE-001", now)
	if !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("CreateUserFromInvite() error = %v, want %v", err, ErrInviteExpired)
	}
}

func TestCreateUserFromInviteMapsUniqueViolation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := &postgresRepository{db: db}
	now := time.Now().UTC().Round(time.Second)
	user := &User{ID: uuid.New(), Username: "alice123", PasswordHash: "hashed", PublicKey: "key", CreatedAt: now, UpdatedAt: now}

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT code, created_by, created_at, expires_at, used_at, used_by_user_id
		FROM invites
		WHERE code = $1
		FOR UPDATE
	`)).
		WithArgs("ALPHA-INVITE-001").
		WillReturnRows(sqlmock.NewRows([]string{"code", "created_by", "created_at", "expires_at", "used_at", "used_by_user_id"}).
			AddRow("ALPHA-INVITE-001", "admin", now.Add(-time.Hour), now.Add(time.Hour), nil, nil))
	mock.ExpectExec(regexp.QuoteMeta(`
		INSERT INTO users (id, username, password_hash, public_key, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`)).
		WithArgs(user.ID, user.Username, user.PasswordHash, user.PublicKey, user.CreatedAt, user.UpdatedAt).
		WillReturnError(&pgconn.PgError{Code: "23505"})
	mock.ExpectRollback()

	err = repo.CreateUserFromInvite(context.Background(), user, "ALPHA-INVITE-001", now)
	if !errors.Is(err, ErrUserAlreadyExists) {
		t.Fatalf("CreateUserFromInvite() error = %v, want %v", err, ErrUserAlreadyExists)
	}
}

func TestCreateUserFromInviteReturnsUpdateError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := &postgresRepository{db: db}
	now := time.Now().UTC().Round(time.Second)
	user := &User{ID: uuid.New(), Username: "alice123", PasswordHash: "hashed", PublicKey: "key", CreatedAt: now, UpdatedAt: now}

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT code, created_by, created_at, expires_at, used_at, used_by_user_id
		FROM invites
		WHERE code = $1
		FOR UPDATE
	`)).
		WithArgs("ALPHA-INVITE-001").
		WillReturnRows(sqlmock.NewRows([]string{"code", "created_by", "created_at", "expires_at", "used_at", "used_by_user_id"}).
			AddRow("ALPHA-INVITE-001", "admin", now.Add(-time.Hour), now.Add(time.Hour), nil, nil))
	mock.ExpectExec(regexp.QuoteMeta(`
		INSERT INTO users (id, username, password_hash, public_key, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`)).
		WithArgs(user.ID, user.Username, user.PasswordHash, user.PublicKey, user.CreatedAt, user.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(regexp.QuoteMeta(`
		UPDATE invites
		SET used_at = $2, used_by_user_id = $3
		WHERE code = $1
	`)).
		WithArgs("ALPHA-INVITE-001", now, user.ID).
		WillReturnError(errors.New("update failed"))
	mock.ExpectRollback()

	err = repo.CreateUserFromInvite(context.Background(), user, "ALPHA-INVITE-001", now)
	if err == nil || !regexp.MustCompile(`mark invite as used`).MatchString(err.Error()) {
		t.Fatalf("CreateUserFromInvite() error = %v, want wrapped update error", err)
	}
}

func TestCreateUserFromInviteReturnsCommitError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := &postgresRepository{db: db}
	now := time.Now().UTC().Round(time.Second)
	user := &User{ID: uuid.New(), Username: "alice123", PasswordHash: "hashed", PublicKey: "key", CreatedAt: now, UpdatedAt: now}

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT code, created_by, created_at, expires_at, used_at, used_by_user_id
		FROM invites
		WHERE code = $1
		FOR UPDATE
	`)).
		WithArgs("ALPHA-INVITE-001").
		WillReturnRows(sqlmock.NewRows([]string{"code", "created_by", "created_at", "expires_at", "used_at", "used_by_user_id"}).
			AddRow("ALPHA-INVITE-001", "admin", now.Add(-time.Hour), now.Add(time.Hour), nil, nil))
	mock.ExpectExec(regexp.QuoteMeta(`
		INSERT INTO users (id, username, password_hash, public_key, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`)).
		WithArgs(user.ID, user.Username, user.PasswordHash, user.PublicKey, user.CreatedAt, user.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(regexp.QuoteMeta(`
		UPDATE invites
		SET used_at = $2, used_by_user_id = $3
		WHERE code = $1
	`)).
		WithArgs("ALPHA-INVITE-001", now, user.ID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit().WillReturnError(errors.New("commit failed"))

	err = repo.CreateUserFromInvite(context.Background(), user, "ALPHA-INVITE-001", now)
	if err == nil || !regexp.MustCompile(`commit register tx`).MatchString(err.Error()) {
		t.Fatalf("CreateUserFromInvite() error = %v, want wrapped commit error", err)
	}
}

func TestCreateUserFromInviteReturnsBeginError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	repo := &postgresRepository{db: db}
	mock.ExpectBegin().WillReturnError(errors.New("begin failed"))

	err = repo.CreateUserFromInvite(context.Background(), &User{}, "ALPHA-INVITE-001", time.Now().UTC())
	if err == nil || !regexp.MustCompile(`begin tx`).MatchString(err.Error()) {
		t.Fatalf("CreateUserFromInvite() error = %v, want wrapped begin error", err)
	}
}

func TestFindInviteForUpdateReturnsNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("db.Begin() error = %v", err)
	}
	defer tx.Rollback()

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT code, created_by, created_at, expires_at, used_at, used_by_user_id
		FROM invites
		WHERE code = $1
		FOR UPDATE
	`)).
		WithArgs("UNKNOWN").
		WillReturnError(sql.ErrNoRows)

	_, err = findInviteForUpdate(context.Background(), tx, "UNKNOWN")
	if !errors.Is(err, ErrInviteNotFound) {
		t.Fatalf("findInviteForUpdate() error = %v, want %v", err, ErrInviteNotFound)
	}
}

func TestScanInviteRejectsInvalidUsedByUUID(t *testing.T) {
	row := scannerStub{
		scan: func(dest ...any) error {
			*dest[0].(*string) = "ALPHA-INVITE-001"
			*dest[1].(*string) = "admin"
			*dest[2].(*time.Time) = time.Now().UTC()
			*dest[3].(*sql.NullTime) = sql.NullTime{}
			*dest[4].(*sql.NullTime) = sql.NullTime{}
			*dest[5].(*sql.NullString) = sql.NullString{String: "bad-uuid", Valid: true}
			return nil
		},
	}

	_, err := scanInvite(row)
	if err == nil {
		t.Fatal("scanInvite() error = nil, want parse error")
	}
}

func TestIsUniqueViolationFalse(t *testing.T) {
	if isUniqueViolation(fmt.Errorf("plain error")) {
		t.Fatal("isUniqueViolation() = true, want false")
	}
}

type scannerStub struct {
	scan func(dest ...any) error
}

func (s scannerStub) Scan(dest ...any) error {
	return s.scan(dest...)
}
