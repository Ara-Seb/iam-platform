package utils

import "net/url"

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
