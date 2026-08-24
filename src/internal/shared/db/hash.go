package db

import (
	"crypto/sha256"
	"encoding/hex"
)

func SHA256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
