//go:build cgo

package store

/*
#cgo pkg-config: sqlite3
#include <sqlite3.h>
#include <stdlib.h>

static int sg_bind_text(sqlite3_stmt *stmt, int index, const char *value) {
    return sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type sqliteDB struct {
	ptr *C.sqlite3
}

type sqliteStmt struct {
	db  *sqliteDB
	ptr *C.sqlite3_stmt
}

func openSQLite(path string) (*sqliteDB, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var raw *C.sqlite3
	flags := C.int(C.SQLITE_OPEN_READWRITE | C.SQLITE_OPEN_CREATE | C.SQLITE_OPEN_FULLMUTEX)
	if rc := C.sqlite3_open_v2(cPath, &raw, flags, nil); rc != C.SQLITE_OK {
		message := "open sqlite"
		if raw != nil {
			message = C.GoString(C.sqlite3_errmsg(raw))
			C.sqlite3_close_v2(raw)
		}
		return nil, fmt.Errorf("sqlite: %s", message)
	}
	C.sqlite3_extended_result_codes(raw, 1)
	return &sqliteDB{ptr: raw}, nil
}

func (db *sqliteDB) close() error {
	if db == nil || db.ptr == nil {
		return nil
	}
	if rc := C.sqlite3_close_v2(db.ptr); rc != C.SQLITE_OK {
		return db.error(rc)
	}
	db.ptr = nil
	return nil
}

func (db *sqliteDB) error(rc C.int) error {
	return fmt.Errorf("sqlite rc=%d: %s", int(rc), C.GoString(C.sqlite3_errmsg(db.ptr)))
}

func (db *sqliteDB) exec(query string) error {
	cQuery := C.CString(query)
	defer C.free(unsafe.Pointer(cQuery))
	var message *C.char
	rc := C.sqlite3_exec(db.ptr, cQuery, nil, nil, &message)
	if message != nil {
		defer C.sqlite3_free(unsafe.Pointer(message))
	}
	if rc != C.SQLITE_OK {
		if message != nil {
			return fmt.Errorf("sqlite rc=%d: %s", int(rc), C.GoString(message))
		}
		return db.error(rc)
	}
	return nil
}

func (db *sqliteDB) prepare(query string) (*sqliteStmt, error) {
	cQuery := C.CString(query)
	defer C.free(unsafe.Pointer(cQuery))
	var raw *C.sqlite3_stmt
	if rc := C.sqlite3_prepare_v2(db.ptr, cQuery, -1, &raw, nil); rc != C.SQLITE_OK {
		return nil, db.error(rc)
	}
	return &sqliteStmt{db: db, ptr: raw}, nil
}

func (db *sqliteDB) changes() int64 {
	return int64(C.sqlite3_changes64(db.ptr))
}

func (stmt *sqliteStmt) close() error {
	if stmt == nil || stmt.ptr == nil {
		return nil
	}
	if rc := C.sqlite3_finalize(stmt.ptr); rc != C.SQLITE_OK {
		return stmt.db.error(rc)
	}
	stmt.ptr = nil
	return nil
}

func (stmt *sqliteStmt) bindText(index int, value string) error {
	cValue := C.CString(value)
	defer C.free(unsafe.Pointer(cValue))
	if rc := C.sg_bind_text(stmt.ptr, C.int(index), cValue); rc != C.SQLITE_OK {
		return stmt.db.error(rc)
	}
	return nil
}

func (stmt *sqliteStmt) bindInt64(index int, value int64) error {
	if rc := C.sqlite3_bind_int64(stmt.ptr, C.int(index), C.sqlite3_int64(value)); rc != C.SQLITE_OK {
		return stmt.db.error(rc)
	}
	return nil
}

func (stmt *sqliteStmt) bindNull(index int) error {
	if rc := C.sqlite3_bind_null(stmt.ptr, C.int(index)); rc != C.SQLITE_OK {
		return stmt.db.error(rc)
	}
	return nil
}

func (stmt *sqliteStmt) step() (bool, error) {
	switch rc := C.sqlite3_step(stmt.ptr); rc {
	case C.SQLITE_ROW:
		return true, nil
	case C.SQLITE_DONE:
		return false, nil
	default:
		return false, stmt.db.error(rc)
	}
}

func (stmt *sqliteStmt) columnText(index int) string {
	value := C.sqlite3_column_text(stmt.ptr, C.int(index))
	if value == nil {
		return ""
	}
	return C.GoString((*C.char)(unsafe.Pointer(value)))
}

func (stmt *sqliteStmt) columnInt64(index int) int64 {
	return int64(C.sqlite3_column_int64(stmt.ptr, C.int(index)))
}

func (stmt *sqliteStmt) columnIsNull(index int) bool {
	return C.sqlite3_column_type(stmt.ptr, C.int(index)) == C.SQLITE_NULL
}
