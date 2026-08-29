//go:build !cgo

package store

import "fmt"

type sqliteDB struct{}
type sqliteStmt struct{}

func noCGOError() error {
	return fmt.Errorf("SG InfoSec SQLite store requires a build with CGO enabled")
}

func openSQLite(string) (*sqliteDB, error)            { return nil, noCGOError() }
func (*sqliteDB) close() error                        { return nil }
func (*sqliteDB) exec(string) error                   { return noCGOError() }
func (*sqliteDB) prepare(string) (*sqliteStmt, error) { return nil, noCGOError() }
func (*sqliteDB) changes() int64                      { return 0 }
func (*sqliteStmt) close() error                      { return nil }
func (*sqliteStmt) bindText(int, string) error        { return noCGOError() }
func (*sqliteStmt) bindInt64(int, int64) error        { return noCGOError() }
func (*sqliteStmt) bindNull(int) error                { return noCGOError() }
func (*sqliteStmt) step() (bool, error)               { return false, noCGOError() }
func (*sqliteStmt) columnText(int) string             { return "" }
func (*sqliteStmt) columnInt64(int) int64             { return 0 }
func (*sqliteStmt) columnIsNull(int) bool             { return true }
