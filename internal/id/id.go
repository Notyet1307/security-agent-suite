package id

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

func New(prefix string, now time.Time) (string, error) {
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("generate id entropy: %w", err)
	}
	return fmt.Sprintf("%s_%d_%s", prefix, now.UTC().UnixMilli(), hex.EncodeToString(entropy[:])), nil
}
