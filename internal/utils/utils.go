package utils

import (
	"encoding/base64"
	"math/rand/v2"
	"net"
	"net/url"

	"github.com/yylego/must"
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

func BooleanToNum(b bool) int {
	if b {
		return 1
	}
	return 0
}

func ExtractPort(endpoint *url.URL) string {
	must.Full(endpoint)
	_, port, _ := net.SplitHostPort(must.Nice(endpoint.Host))
	return must.Nice(port)
}
