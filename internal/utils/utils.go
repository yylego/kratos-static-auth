package utils

import (
	"encoding/base64"
	"math/rand/v2"
)

func BasicEncode(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

func BasicAuth(username, password string) string {
	return "Basic " + BasicEncode(username, password)
}

func Sample[T any](a []T) (res T) {
	if len(a) > 0 {
		res = a[rand.IntN(len(a))]
	}
	return res
}
