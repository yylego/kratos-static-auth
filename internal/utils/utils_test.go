package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBasicEncode(t *testing.T) {
	require.Equal(t, "YWRtaW46c2VjcmV0LXRva2VuLTEyMw==", BasicEncode("admin", "secret-token-123"))
}

func TestBasicAuth(t *testing.T) {
	require.Equal(t, "Basic YWRtaW46c2VjcmV0LXRva2VuLTEyMw==", BasicAuth("admin", "secret-token-123"))
}

func TestSample(t *testing.T) {
	require.Equal(t, "admin", Sample([]string{"admin"}))
	require.Contains(t, []string{"admin", "guest"}, Sample([]string{"admin", "guest"}))
	require.Equal(t, "", Sample([]string{}))
}
