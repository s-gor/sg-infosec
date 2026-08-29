package store

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const currentSchemaVersion = 1

//go:embed migrations/001_init.sql
var initialMigration string

type Store struct {
	mu     sync.Mutex
	db     *sqliteDB
	path   string
	closed bool
}

type Tx struct {
	store *Store
	db    *sqliteDB
}

func Open(ctx context.Context, path string) (*Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("database path is required")
	}
	parent := filepath.Dir(path)
	if info, err := os.Stat(parent); err != nil {
		return nil, fmt.Errorf("database parent directory: %w", err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("database parent %s is not a directory", parent)
	}
	db, err := openSQLite(path)
	if err != nil {
		return nil, err
	}
	store := &Store{db: db, path: path}
	if err := store.initialize(ctx); err != nil {
		db.close()
		return nil, err
	}
	return store, nil
}

func (s *Store) initialize(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, pragma := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA synchronous = NORMAL",
	} {
		if err := s.db.exec(pragma); err != nil {
			return err
		}
	}
	if err := s.db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return err
	}
	version, err := scalarInt64(s.db, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
	if err != nil {
		return err
	}
	if version > currentSchemaVersion {
		return fmt.Errorf("database schema version %d is newer than supported version %d", version, currentSchemaVersion)
	}
	if version == currentSchemaVersion {
		return nil
	}
	if err := s.db.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = s.db.exec("ROLLBACK")
		}
	}()
	if err := s.db.exec(initialMigration); err != nil {
		return err
	}
	if err := s.db.exec("COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.close()
}

func (s *Store) WithTx(ctx context.Context, fn func(*Tx) error) error {
	if fn == nil {
		return fmt.Errorf("transaction function is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("store is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.db.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = s.db.exec("ROLLBACK")
		}
	}()
	if err := fn(&Tx{store: s, db: s.db}); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.db.exec("COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

func scalarInt64(db *sqliteDB, query string) (int64, error) {
	stmt, err := db.prepare(query)
	if err != nil {
		return 0, err
	}
	defer stmt.close()
	row, err := stmt.step()
	if err != nil {
		return 0, err
	}
	if !row {
		return 0, fmt.Errorf("query returned no row")
	}
	return stmt.columnInt64(0), nil
}

func scalarText(db *sqliteDB, query string) (string, error) {
	stmt, err := db.prepare(query)
	if err != nil {
		return "", err
	}
	defer stmt.close()
	row, err := stmt.step()
	if err != nil {
		return "", err
	}
	if !row {
		return "", fmt.Errorf("query returned no row")
	}
	return stmt.columnText(0), nil
}
