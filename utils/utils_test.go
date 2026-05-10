package utils

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateCodeVerifier_TooLong(t *testing.T) {
	var codeVerifier strings.Builder
	for range 129 {
		codeVerifier.WriteString("a")
	}
	assert.False(t, ValidateCodeVerifier(codeVerifier.String()))
}

func TestValidateCodeVerifier_TooShort(t *testing.T) {
	var codeVerifier strings.Builder
	for range 42 {
		codeVerifier.WriteString("a")
	}
	assert.False(t, ValidateCodeVerifier(codeVerifier.String()))
}

func TestValidateCodeVerifier_InvalidCharacters(t *testing.T) {
	var codeVerifier strings.Builder
	for range 42 {
		codeVerifier.WriteString("a")
	}
	codeVerifier.WriteString("+")
	assert.False(t, ValidateCodeVerifier(codeVerifier.String()))
}

func TestValidateCodeVerifier_Valid(t *testing.T) {
	var codeVerifier strings.Builder
	for range 43 {
		codeVerifier.WriteString("a")
	}
	codeVerifier.WriteString("~._-0A")
	assert.True(t, ValidateCodeVerifier(codeVerifier.String()))
}
