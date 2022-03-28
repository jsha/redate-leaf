package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const treeId = 9876
const entryIndex = 543

func setupDB(mirroredLeafValue []byte) (*sql.DB, error) {
	dsn := os.Getenv("DB")
	if dsn == "" {
		return nil, fmt.Errorf("$DB is unset; put a DB connection string in $DB")
	}
	db, err := sql.Open("mysql", os.Getenv("DB"))
	if err != nil {
		return nil, fmt.Errorf("opening DB: %w", err)
	}

	var dbInitCommands = []string{
		`DROP TABLE IF EXISTS SequencedLeafData`,
		`DROP TABLE IF EXISTS LeafData`,
		`DROP TABLE IF EXISTS Trees`,
		// https: //github.com/google/trillian/blob/998c07765e8725c8ee53fb16736b25771013916e/storage/mysql/schema/storage.sql#L9-L26
		`
		CREATE TABLE IF NOT EXISTS Trees(
			TreeId                BIGINT NOT NULL,
			PRIMARY KEY(TreeId)
		  )
		`,
		`INSERT INTO Trees (TreeId) VALUES (9876)`,
		// https://github.com/google/trillian/blob/998c07765e8725c8ee53fb16736b25771013916e/storage/mysql/schema/storage.sql#L94-L114
		`
-- A leaf that has not been sequenced has a row in this table. If duplicate leaves
-- are allowed they will all reference this row.
CREATE TABLE IF NOT EXISTS LeafData(
  TreeId               BIGINT NOT NULL,
  -- This is a personality specific has of some subset of the leaf data.
  -- It's only purpose is to allow Trillian to identify duplicate entries in
  -- the context of the personality.
  LeafIdentityHash     VARBINARY(255) NOT NULL,
  -- This is the data stored in the leaf for example in CT it contains a DER encoded
  -- X.509 certificate but is application dependent
  LeafValue            LONGBLOB NOT NULL,
  -- This is extra data that the application can associate with the leaf should it wish to.
  -- This data is not included in signing and hashing.
  ExtraData            LONGBLOB,
  -- The timestamp from when this leaf data was first queued for inclusion.
  QueueTimestampNanos  BIGINT NOT NULL,
  PRIMARY KEY(TreeId, LeafIdentityHash),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE
);
		`,
		// https://github.com/google/trillian/blob/998c07765e8725c8ee53fb16736b25771013916e/storage/mysql/schema/storage.sql#L94-L114
		`
CREATE TABLE IF NOT EXISTS SequencedLeafData(
  TreeId               BIGINT NOT NULL,
  SequenceNumber       BIGINT UNSIGNED NOT NULL,
  -- This is a personality specific has of some subset of the leaf data.
  -- It's only purpose is to allow Trillian to identify duplicate entries in
  -- the context of the personality.
  LeafIdentityHash     VARBINARY(255) NOT NULL,
  -- This is a MerkleLeafHash as defined by the treehasher that the log uses. For example for
  -- CT this hash will include the leaf prefix byte as well as the leaf data.
  MerkleLeafHash       VARBINARY(255) NOT NULL,
  IntegrateTimestampNanos BIGINT NOT NULL,
  PRIMARY KEY(TreeId, SequenceNumber),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE,
  FOREIGN KEY(TreeId, LeafIdentityHash) REFERENCES LeafData(TreeId, LeafIdentityHash) ON DELETE CASCADE
);
		`,
	}

	for _, command := range dbInitCommands {
		_, err = db.Exec(command)
		if err != nil {
			return nil, fmt.Errorf("initializing DB: %q: %w", command, err)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}

	// From curl 'https://oak.ct.letsencrypt.org/2022/ct/v1/get-entries?start=138892498&end=138892498' | jq ".entries[0].leaf_input"
	// Executed on 2022-03-28
	leafValueB64 := "AAAAAAF9nFyciwABJSMzqOOrtyOT1kmau6zKhgT676hGgczD5VMdRMyJZFAAA0MwggM/oAMCAQICEA9MP5PskfglCZz0jfBFa+8wDQYJKoZIhvcNAQELBQAwRjELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENBIDFCMQ8wDQYDVQQDEwZBbWF6b24wHhcNMjExMTI2MDAwMDAwWhcNMjIxMjI0MjM1OTU5WjAUMRIwEAYDVQQDEwlwNHRjaC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVT1ReJ2lJVDgznr3M98lOhfyx0q4PQGLrfvfP8AIpf3eYLEC3umntHbOUKvKPOnW4n8tWTPhWhy17/JIkGwO0t3N3gO4wNkm3jnRe7fXk7a+BYxehSq0vO7J0Mxiqb0S84m6wiXKALl8iBw+gZh18svQYpmA8+VWRYcgULSHkbw53FHB7iFvyUOQLLhnItM7etyzC77eGsUfXGVNGuROn8FleYIFd2y97vEhDpcYCjGs9dx99yN/2Q1QwomMnYwUMd/9oMZMA/4arPNJnbLz7p31dP97d8Nxg06LUYKHHFeUuER62Yw+hWFfxgjPRLYIW6tNPypUWsAMk1K6XlVRXAgMBAAGjggFxMIIBbTAfBgNVHSMEGDAWgBRZpGYGUqB7lZI8o5QHJ5Z0W/k90DAdBgNVHQ4EFgQUDyvdZgmgcg6ksvLlknpokVXf9YswIwYDVR0RBBwwGoIJcDR0Y2guY29tgg13d3cucDR0Y2guY29tMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwPQYDVR0fBDYwNDAyoDCgLoYsaHR0cDovL2NybC5zY2ExYi5hbWF6b250cnVzdC5jb20vc2NhMWItMS5jcmwwEwYDVR0gBAwwCjAIBgZngQwBAgEwdQYIKwYBBQUHAQEEaTBnMC0GCCsGAQUFBzABhiFodHRwOi8vb2NzcC5zY2ExYi5hbWF6b250cnVzdC5jb20wNgYIKwYBBQUHMAKGKmh0dHA6Ly9jcnQuc2NhMWIuYW1hem9udHJ1c3QuY29tL3NjYTFiLmNydDAMBgNVHRMBAf8EAjAAAAA="
	leafValue, err := base64.StdEncoding.DecodeString(leafValueB64)
	if err != nil {
		return nil, fmt.Errorf("decoding leafValue: %w", err)
	}

	// Fake leaf identity hash: random bytes
	var leafIdentityHash [32]byte
	rand.Read(leafIdentityHash[:])
	leafData := &LeafData{
		TreeId:              treeId,
		LeafIdentityHash:    leafIdentityHash[:],
		LeafValue:           leafValue,
		ExtraData:           nil,
		QueueTimestampNanos: time.Now().UnixNano(),
	}
	err = insertLeafData(tx, leafData)
	if err != nil {
		return nil, err
	}

	mirroredMerkleLeafHash := sha256.Sum256(mirroredLeafValue)
	sequencedLeaf := &SequencedLeaf{
		TreeId:                  treeId,
		LeafIdentityHash:        leafIdentityHash[:],
		MerkleLeafHash:          mirroredMerkleLeafHash[:],
		SequenceNumber:          entryIndex,
		IntegrateTimestampNanos: time.Now().UnixNano(),
	}
	err = insertSequencedLeaf(tx, sequencedLeaf)
	if err != nil {
		return nil, err
	}

	duplicateEntryMerkleLeafHash := sha256.Sum256(leafValue)
	sequencedLeaf2 := &SequencedLeaf{
		TreeId:                  treeId,
		LeafIdentityHash:        leafIdentityHash[:],
		MerkleLeafHash:          duplicateEntryMerkleLeafHash[:],
		SequenceNumber:          entryIndex + 1,
		IntegrateTimestampNanos: time.Now().UnixNano(),
	}
	err = insertSequencedLeaf(tx, sequencedLeaf2)
	if err != nil {
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	return db, nil
}

func insertSequencedLeaf(tx *sql.Tx, sequencedLeaf *SequencedLeaf) error {
	const insertSequencedLeafSQL = `INSERT INTO
		SequencedLeafData(TreeId, LeafIdentityHash, MerkleLeafHash, SequenceNumber, IntegrateTimestampNanos)
		VALUES (?, ?, ?, ?, ?)`
	_, err := tx.Exec(insertSequencedLeafSQL,
		sequencedLeaf.TreeId,
		sequencedLeaf.LeafIdentityHash,
		sequencedLeaf.MerkleLeafHash,
		sequencedLeaf.SequenceNumber,
		sequencedLeaf.IntegrateTimestampNanos)
	return err
}

func TestRedateLeaf(t *testing.T) {
	// From curl 'https://ct.googleapis.com/logs/eu1/mirrors/letsencrypt_oak2022/ct/v1/get-entries?start=138892498&end=138892498' | jq ".entries[0].leaf_input"
	mirroredLeafValueB64 := "AAAAAAF9Wi9GAwABJSMzqOOrtyOT1kmau6zKhgT676hGgczD5VMdRMyJZFAAA0MwggM/oAMCAQICEA9MP5PskfglCZz0jfBFa+8wDQYJKoZIhvcNAQELBQAwRjELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENBIDFCMQ8wDQYDVQQDEwZBbWF6b24wHhcNMjExMTI2MDAwMDAwWhcNMjIxMjI0MjM1OTU5WjAUMRIwEAYDVQQDEwlwNHRjaC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVT1ReJ2lJVDgznr3M98lOhfyx0q4PQGLrfvfP8AIpf3eYLEC3umntHbOUKvKPOnW4n8tWTPhWhy17/JIkGwO0t3N3gO4wNkm3jnRe7fXk7a+BYxehSq0vO7J0Mxiqb0S84m6wiXKALl8iBw+gZh18svQYpmA8+VWRYcgULSHkbw53FHB7iFvyUOQLLhnItM7etyzC77eGsUfXGVNGuROn8FleYIFd2y97vEhDpcYCjGs9dx99yN/2Q1QwomMnYwUMd/9oMZMA/4arPNJnbLz7p31dP97d8Nxg06LUYKHHFeUuER62Yw+hWFfxgjPRLYIW6tNPypUWsAMk1K6XlVRXAgMBAAGjggFxMIIBbTAfBgNVHSMEGDAWgBRZpGYGUqB7lZI8o5QHJ5Z0W/k90DAdBgNVHQ4EFgQUDyvdZgmgcg6ksvLlknpokVXf9YswIwYDVR0RBBwwGoIJcDR0Y2guY29tgg13d3cucDR0Y2guY29tMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwPQYDVR0fBDYwNDAyoDCgLoYsaHR0cDovL2NybC5zY2ExYi5hbWF6b250cnVzdC5jb20vc2NhMWItMS5jcmwwEwYDVR0gBAwwCjAIBgZngQwBAgEwdQYIKwYBBQUHAQEEaTBnMC0GCCsGAQUFBzABhiFodHRwOi8vb2NzcC5zY2ExYi5hbWF6b250cnVzdC5jb20wNgYIKwYBBQUHMAKGKmh0dHA6Ly9jcnQuc2NhMWIuYW1hem9udHJ1c3QuY29tL3NjYTFiLmNydDAMBgNVHRMBAf8EAjAAAAA="
	mirroredLeafValue, err := base64.StdEncoding.DecodeString(mirroredLeafValueB64)
	if err != nil {
		t.Fatal(err)
	}

	db, err := setupDB(mirroredLeafValue)
	if err != nil {
		t.Fatal(err)
	}

	csvLine := fmt.Sprintf("%d,%x", entryIndex, mirroredLeafValue)
	reader := csv.NewReader(strings.NewReader(csvLine))

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	err = processRow(tx, reader, treeId)
	if err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
}
