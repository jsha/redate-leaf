// A tool to fix up a CT log where the date of one entry is incorrect because the LeafData
// for that entry belongs to a later submission of the same certificate or precertificate.
package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

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
	flag.Parse()

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

	reader := csv.NewReader(os.Stdin)
	for {
		err := processRow(tx, reader, *treeId)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			err2 := tx.Rollback()
			if err2 != nil {
				return fmt.Errorf("%w; also, while rolling back: %s", err, err2)
			}
			return fmt.Errorf("%w (rolled back)", err)
		}

	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

func processRow(tx *sql.Tx, reader *csv.Reader, treeId int64) error {
	record, err := reader.Read()
	if err != nil {
		return fmt.Errorf("scanning CSV: %w", err)
	}

	if len(record) != 2 {
		return fmt.Errorf("wrong number of records in CSV file: expected 2, got %d", len(record))
	}
	indexString := record[0]
	merkleLeafBytes, err := hex.DecodeString(record[1])
	if err != nil {
		return fmt.Errorf("unmarshaling Merkle leaf bytes: %w", err)
	}

	index, err := strconv.ParseInt(indexString, 10, 64)
	if err != nil {
		return fmt.Errorf("parsing %q as int: %w", indexString, err)
	}

	err = redateLeaf(tx, treeId, index, merkleLeafBytes)
	if err != nil {
		return err
	}
	return nil
}

// redateLeaf runs the logic of this tool, inside a DB transaction:
//  - Read the entry.
//  - Come up with a new LeafIdentityHash.
//  - Insert a new LeafData with the new LeafIdentityHash, and the corrected timestamp.
//  - Update the SequencedLeaf for `first` to point at the new LeafIdentityHash.
func redateLeaf(tx *sql.Tx, treeId, index int64, correctMerkleLeafBytes []byte) error {
	sequencedLeaf, err := selectSequencedLeaf(tx, treeId, index)
	if err != nil {
		return fmt.Errorf("selecting first leaf: %w", err)
	}

	// Verify our assumptions
	err = expectDuplicateSequencedLeaf(tx, treeId, sequencedLeaf.LeafIdentityHash)
	if err != nil {
		return fmt.Errorf("expected duplicate sequencedLeaf rows with the same LeafIdentityHash, but didn't get them: %w", err)
	}

	// The stored Merkle leaf hash in the SequencedLeafData table is correct; it's just the LeafValue in
	// the LeafData table that's wrong. Verify that.
	correctMerkleHash := sha256.Sum256(correctMerkleLeafBytes)
	if !bytes.Equal(correctMerkleHash[:], sequencedLeaf.MerkleLeafHash) {
		return fmt.Errorf("mismatch: SequencedLeaf.MerkleLeafHash != SHA-256(Merkle Leaf Bytes from CSV): %x vs %x",
			sequencedLeaf.MerkleLeafHash, correctMerkleHash[:])
	}

	// TODO: New leafIdentityHash is the result of hashing the old one a second time. Good enough?
	origLeafIdentityHash := sequencedLeaf.LeafIdentityHash
	newLeafIdentityHash := sha256.Sum256(origLeafIdentityHash)

	// Fetch the existing single LeafData, so we can modify it to have the correct timestamp and
	// save a new copy under newLeafIdentityHash, then update the SequencedLeafData entry to point at it.
	leafData, err := selectLeafData(tx, treeId, origLeafIdentityHash)
	if err != nil {
		return fmt.Errorf("selecting leaf data for origLeafIdentityHash %x: %w", origLeafIdentityHash, err)
	}

	// leafData.LeafValue contains the TLS-encoded Merkle tree leaf, which in turn contains
	// the timestamp we care about. Decode it (umarshal it) so we can modify the timestamp and
	// re-encode.
	var brokenMerkleLeaf ct.MerkleTreeLeaf
	_, err = tls.Unmarshal(leafData.LeafValue, &brokenMerkleLeaf)
	if err != nil {
		return fmt.Errorf("unmarshaling leaf data %x: %w", leafData.LeafValue, err)
	}

	var correctMerkleLeaf ct.MerkleTreeLeaf
	_, err = tls.Unmarshal(correctMerkleLeafBytes, &correctMerkleLeaf)
	if err != nil {
		return fmt.Errorf("unmarshaling Merkle Leaf Bytes from CSV %x: %w", correctMerkleLeafBytes, err)
	}

	newTimestamp := correctMerkleLeaf.TimestampedEntry.Timestamp
	brokenMerkleLeaf.TimestampedEntry.Timestamp = newTimestamp

	// The updated, TLS-encoded Merkle tree leaf.
	newLeafValue, err := tls.Marshal(brokenMerkleLeaf)
	if err != nil {
		return fmt.Errorf("marshaling modified Merkle tree leaf: %w", err)
	}

	fixedMerkleLeafHash := sha256.Sum256(newLeafValue)
	if !bytes.Equal(fixedMerkleLeafHash[:], sequencedLeaf.MerkleLeafHash) {
		return fmt.Errorf("mismatch: SequencedLeaf.MerkleLeafHash != SHA-256(newLeafValue): %x vs %x",
			sequencedLeaf.MerkleLeafHash, correctMerkleHash[:])
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
	err = updateSequencedLeaf(tx, sequencedLeaf, newLeafData)
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
		TreeId, LeafIdentityHash, MerkleLeafHash, SequenceNumber, IntegrateTimestampNanos
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

func expectDuplicateSequencedLeaf(tx *sql.Tx, treeId int64, leafIdentityHash []byte) error {
	const selectSequencedLeafSQL = `SELECT
	    COUNT(*)
	    FROM SequencedLeafData
		WHERE TreeId = ?
		AND LeafIdentityHash = ?`
	row := tx.QueryRow(selectSequencedLeafSQL, treeId, leafIdentityHash)
	var count int64
	err := row.Scan(&count)
	if err != nil {
		return fmt.Errorf("checking for duplicates: scanning row: %w", err)
	}
	if count != 2 {
		return fmt.Errorf("expected exactly 2 duplicate SequencedLeafData with LeafIdentityHash %x, got %d", leafIdentityHash)
	}
	return nil
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
		TreeId, LeafIdentityHash, LeafValue, ExtraData, QueueTimestampNanos
		FROM LeafData
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
