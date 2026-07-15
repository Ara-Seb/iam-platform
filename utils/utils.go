package utils

import (
	"net/url"
	"regexp"
)

var regexCodeVerifier = regexp.MustCompile(`^[a-zA-Z0-9\-\._~]+$`)

func Contains[T comparable](slice []T, val T) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func BuildRedirectURI(baseURI string, code string, state string) string {
	u, _ := url.Parse(baseURI)
	q := u.Query()
	q.Set("code", code)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

func BuildErrorRedirectURI(baseURI string, errorCode string, state string) string {
	u, _ := url.Parse(baseURI)
	q := u.Query()
	q.Set("error", errorCode)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

func ValidateCodeVerifier(codeVerifier string) bool {
	return len(codeVerifier) >= 43 && len(codeVerifier) <= 128 && regexCodeVerifier.MatchString(codeVerifier)
}
