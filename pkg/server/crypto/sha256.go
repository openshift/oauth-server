package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

const SHA256Prefix = "sha256~"

func TrimSHA256Prefix(code string) (string, bool) {
	if !strings.HasPrefix(code, SHA256Prefix) {
		return code, false
	}
	return strings.TrimPrefix(code, SHA256Prefix), true
}

func SHA256Token(token string) string {
	h := sha256.Sum256([]byte(token))
	return SHA256Prefix + base64.RawURLEncoding.EncodeToString(h[0:])
}
