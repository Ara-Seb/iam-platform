package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const validVerifier = "atLeast43CharactersLongCodeVerifierWhichIsValid"

func TestVerifyCodeChallenge_S256_Valid(t *testing.T) {
	challenge := SHA256Hash(validVerifier)
	assert.True(t, VerifyCodeChallenge(validVerifier, challenge, "S256"))
}

func TestVerifyCodeChallenge_S256_Invalid(t *testing.T) {
	challenge := SHA256Hash(validVerifier)
	assert.False(t, VerifyCodeChallenge("wrongverifierbutstilllongenoughtobechecked1234", challenge, "S256"))
}

func TestVerifyCodeChallenge_Plain_Valid(t *testing.T) {
	assert.True(t, VerifyCodeChallenge(validVerifier, validVerifier, "plain"))
}

func TestVerifyCodeChallenge_Plain_Invalid(t *testing.T) {
	assert.False(t, VerifyCodeChallenge(validVerifier, "wrongchallenge", "plain"))
}

func TestVerifyCodeChallenge_UnknownMethod(t *testing.T) {
	assert.False(t, VerifyCodeChallenge(validVerifier, validVerifier, "unknown"))
}
