// A tool to fix up a CT log where the date of one entry is incorrect because the LeafData
// for that entry belongs to a later submission of the same certificate or precertificate.
package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
)

func main() {
	err := main2()
	if err != nil {
		log.Fatal(err)
	}
}

func main2() error {
	treeId := flag.Int64("treeId", -1, "Tree ID")
	firstIndex := flag.Int64("first", -1, "Index of first (broken) entry in log to be repaired")
	secondIndex := flag.Int64("second", -1, "Index of second (ok) entry in log to be repaired")
	newTimestamp := flag.Int64("newTimestamp", -1, "New timestamp to assign to first (broken) entry. In epoch milliseconds")

	if *treeId == -1 || *firstIndex == -1 || *secondIndex == -1 {
		flag.Usage()
		return fmt.Errorf("invalid flags")
	}

	dsn := os.Getenv("DB")
	if dsn == "" {
		return fmt.Errorf("$DB is unset; put a DB connection string in $DB")
	}
	db, err := sql.Open("mysql", os.Getenv("DB"))
	if err != nil {
		return fmt.Errorf("opening DB: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}

	err = transact(tx, *treeId, *firstIndex, *secondIndex, *newTimestamp)
	if err != nil {
		err2 := tx.Rollback()
		if err2 != nil {
			return fmt.Errorf("%w; also, while rolling back: %w", err, err2)
		}
		return fmt.Errorf("%w (rolled back)", err)
	}
	return nil
}

// transact runs the logic of this tool, inside a DB transaction:
//  - Read both entries.
//  - Confirm they point at the same LeafIdentityHash.
//  - Come up with a new LeafIdentityHash.
//  - Insert a new LeafData with the new LeafIdentityHash, and the corrected timestamp.
//  - Update the SequencedLeaf for `first` to point at the new LeafIdentityHash.
func transact(tx *sql.Tx, treeId, firstIndex, secondIndex, newTimestamp int64) error {
	first, err := selectSequencedLeaf(tx, treeId, firstIndex)
	if err != nil {
		return err
	}
	second, err := selectSequencedLeaf(tx, treeId, firstIndex)
	if err != nil {
		return err
	}

	// Verify our assumptions
	if !bytes.Equal(first.LeafIdentityHash, second.LeafIdentityHash) {
		return fmt.Errorf("expected LeafIdentityHashes to be equal but they weren't. %d: %x; %d: %x",
			firstIndex, first.LeafIdentityHash, secondIndex, second.LeafIdentityHash)
	}

	// The two SequencedLeaf entries point at a single LeafData, because they have the same
	// LeafIdentityHash.
	origLeafIdentityHash := first.LeafIdentityHash
	// TODO: New leafIdentityHash is the result of hashing the old one a second time. Good enough?
	newLeafIdentityHash := sha256.Sum256(origLeafIdentityHash)

	// Fetch the existing single LeafData, so we can modify it to have the correct timestamp and
	// save a new copy under newLeafIdentityHash, then update `first` to point at it.
	leafData, err := selectLeafData(tx, treeId, origLeafIdentityHash)
	if err != nil {
		return fmt.Errorf("selecting leaf data: %w", err)
	}

	// leafData.LeafValue contains the TLS-encoded Merkle tree leaf, which in turn contains
	// the timestamp we care about. Decode it (umarshal it) so we can modify the timestamp and
	// re-encode.
	var merkleLeaf ct.MerkleTreeLeaf
	_, err = tls.Unmarshal(leafData.LeafValue, &merkleLeaf)
	if err != nil {
		return fmt.Errorf("unmarshaling leaf data: %w", err)
	}

	merkleLeaf.TimestampedEntry.Timestamp = uint64(newTimestamp)

	// The updated, TLS-encoded Merkle tree leaf.
	newLeafValue, err := tls.Marshal(merkleLeaf)
	if err != nil {
		return fmt.Errorf("marshaling modified Merkle tree leaf: %w", err)
	}

	// The updated Trillian-internal data structure that contains the Merkle tree leaf.
	newLeafData := leafData
	newLeafData.LeafIdentityHash = newLeafIdentityHash[:]
	newLeafData.LeafValue = newLeafValue

	// Store the updated Trillian-internal data structure (LeafData), indexed by the new LeafIdentityHash.
	err = insertLeafData(tx, newLeafData)
	if err != nil {
		return fmt.Errorf("inserting new LeafData: %w", err)
	}

	// Update the first of the two SequencedLeafs to point at the new LeafData, with the corrected timestamp.
	err = updateSequencedLeaf(tx, first, newLeafData)
	if err != nil {
		return fmt.Errorf("updating sequenced leaf: %w", err)
	}

	return nil
}

// SequencedLeaf represents a row in Trillian's SequencedLeafData table. See:
// https://github.com/google/trillian/blob/998c07765e8725c8ee53fb16736b25771013916e/storage/mysql/schema/storage.sql#L94-L114
// https://github.com/google/trillian/blob/998c07765e8725c8ee53fb16736b25771013916e/storage/mysql/log_storage.go#L46
type SequencedLeaf struct {
	TreeId                  int64
	LeafIdentityHash        []byte
	MerkleLeafHash          []byte
	SequenceNumber          int64
	IntegrateTimestampNanos int64
}

func selectSequencedLeaf(tx *sql.Tx, treeId, index int64) (*SequencedLeaf, error) {
	leaf := new(SequencedLeaf)
	const selectSequencedLeafSQL = `SELECT
		(TreeId, LeafIdentityHash, MerkleLeafHash, SequenceNumber, IntegrateTimestampNanos)
		FROM SequencedLeafData
		WHERE TreeId = ?
		AND SequenceNumber = ?`
	row := tx.QueryRow(selectSequencedLeafSQL, treeId, index)
	return leaf, row.Scan(
		&leaf.TreeId,
		&leaf.LeafIdentityHash,
		&leaf.MerkleLeafHash,
		&leaf.SequenceNumber,
		&leaf.IntegrateTimestampNanos,
	)
}

// updateSequencedLeaf updates an already-existing row in the SequencedLeafData table to point at a new
// LeafIdentityHash. Errors if it fails to update exactly one row.
func updateSequencedLeaf(tx *sql.Tx, sequencedLeaf *SequencedLeaf, newLeafData *LeafData) error {
	if sequencedLeaf.TreeId != newLeafData.TreeId {
		return fmt.Errorf("sequencedLeafTreeId != leafData.TreeId: %d vs %d", sequencedLeaf.TreeId, newLeafData.TreeId)
	}
	const selectSequencedLeafSQL = `UPDATE SequencedLeafData
		SET LeafIdentityHash = ?
		WHERE TreeId = ?
		AND SequenceNumber = ?
		LIMIT 1`
	result, err := tx.Exec(selectSequencedLeafSQL, newLeafData.LeafIdentityHash, sequencedLeaf.TreeId, sequencedLeaf.SequenceNumber)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected != 1 {
		return fmt.Errorf("wrong number of rows affected on insert. expected 1, got %d", rowsAffected)
	}
	return nil
}

// LeafData represents a row in Trillian's LeafData table. See:
//
// https://github.com/google/trillian/blob/998c07765e8725c8ee53fb16736b25771013916e/storage/mysql/schema/storage.sql#L70-L92
// https://github.com/google/trillian/blob/998c07765e8725c8ee53fb16736b25771013916e/storage/mysql/log_storage.go#L45
type LeafData struct {
	TreeId              int64
	LeafIdentityHash    []byte
	LeafValue           []byte
	ExtraData           []byte
	QueueTimestampNanos int64
}

// selectLeafData retrieves a single LeafData entry from the database, indexed by TreeID and LeafIdentityHash.
func selectLeafData(tx *sql.Tx, treeId int64, leafIdentityHash []byte) (*LeafData, error) {
	leafData := new(LeafData)

	const selectLeafDataSQL = `SELECT
		(TreeId, LeafIdentityHash, MerkleLeafHash, SequenceNumber, IntegrateTimestampNanos)
		FROM SequencedLeafData
		WHERE TreeId = ?
		AND LeafIdentityHash = ?`
	row := tx.QueryRow(selectLeafDataSQL, treeId, leafIdentityHash)
	return leafData, row.Scan(
		&leafData.TreeId,
		&leafData.LeafIdentityHash,
		&leafData.LeafValue,
		&leafData.ExtraData,
		&leafData.QueueTimestampNanos,
	)
}

// insertLeafData inserts a single LeafData entry into the database. Errors if an entry already exists with
// the same primary key (TreeID and LeafIdentityHash).
func insertLeafData(tx *sql.Tx, leafData *LeafData) error {
	const insertLeafDataSQL = `INSERT INTO LeafData(TreeId, LeafIdentityHash, LeafValue, ExtraData, QueueTimestampNanos) VALUES (?, ?, ?, ?, ?)`
	result, err := tx.Exec(insertLeafDataSQL,
		leafData.TreeId,
		leafData.LeafIdentityHash,
		leafData.LeafValue,
		leafData.ExtraData,
		leafData.QueueTimestampNanos)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected != 1 {
		return fmt.Errorf("wrong number of rows affected on insert. expected 1, got %d", rowsAffected)
	}
	return nil
}
