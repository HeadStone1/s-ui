package common

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const bcryptPrefix = "$2"

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPasswordHash(password string, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func IsPasswordHash(value string) bool {
	return strings.HasPrefix(value, bcryptPrefix)
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func CheckTokenHash(token string, hash string) bool {
	tokenHash := HashToken(token)
	return subtle.ConstantTimeCompare([]byte(tokenHash), []byte(hash)) == 1
}
