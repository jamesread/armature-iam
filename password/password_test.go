package password

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashVerify(t *testing.T) {
	hash, err := Hash("secret")
	require.NoError(t, err)
	ok, err := Verify(hash, "secret")
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = Verify(hash, "wrong")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestGenerateAPIKeyPrefix(t *testing.T) {
	key, err := GenerateAPIKey("sa_")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(key, "sa_"))
	assert.Len(t, key, 35)
}
