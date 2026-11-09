package password

import (
	"strings"
	"testing"

	"github.com/alexedwards/argon2id"
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

// Parameters each application hashed with before moving to this package.
var legacyParams = map[string]*argon2id.Params{
	"japella and olivetin": {Memory: 64 * 1024, Iterations: 4, Parallelism: 8, SaltLength: 16, KeyLength: 32},
	"faridoon":             {Memory: 64 * 1024, Iterations: 1, Parallelism: 2, SaltLength: 16, KeyLength: 32},
}

func TestVerifyHashesFromApplications(t *testing.T) {
	for name, params := range legacyParams {
		hash, err := argon2id.CreateHash("secret", params)
		require.NoError(t, err, name)

		ok, err := Verify(hash, "secret")
		require.NoError(t, err, name)
		assert.True(t, ok, name)

		ok, err = Verify(hash, "wrong")
		require.NoError(t, err, name)
		assert.False(t, ok, name)
	}
}

func TestNeedsRehash(t *testing.T) {
	current, err := Hash("secret")
	require.NoError(t, err)
	assert.False(t, NeedsRehash(current), "current defaults")

	matching, err := argon2id.CreateHash("secret", legacyParams["japella and olivetin"])
	require.NoError(t, err)
	assert.False(t, NeedsRehash(matching), "same cost with different parallelism")

	weak, err := argon2id.CreateHash("secret", legacyParams["faridoon"])
	require.NoError(t, err)
	assert.True(t, NeedsRehash(weak), "fewer iterations")

	assert.True(t, NeedsRehash("$2a$10$abcdefghijklmnopqrstuv"), "bcrypt")
	assert.True(t, NeedsRehash("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"), "sha1")
	assert.True(t, NeedsRehash(""), "empty")
}

func TestParallelism(t *testing.T) {
	assert.Equal(t, uint8(1), parallelism(0))
	assert.Equal(t, uint8(8), parallelism(8))
	assert.Equal(t, uint8(255), parallelism(255))
	assert.Equal(t, uint8(255), parallelism(256))
	assert.Equal(t, uint8(255), parallelism(1024))
}

func TestLimiter(t *testing.T) {
	limiter := NewLimiter(1)

	hash, err := limiter.Hash("secret")
	require.NoError(t, err)

	ok, err := limiter.Verify(hash, "secret")
	require.NoError(t, err)
	assert.True(t, ok)

	require.True(t, limiter.acquire())
	defer limiter.release()

	_, err = limiter.Hash("secret")
	assert.ErrorIs(t, err, ErrBusy)

	_, err = limiter.Verify(hash, "secret")
	assert.ErrorIs(t, err, ErrBusy)
}

func TestNewLimiterAlwaysAllowsOne(t *testing.T) {
	_, err := NewLimiter(0).Hash("secret")
	assert.NoError(t, err)
}

func TestGenerate(t *testing.T) {
	first, err := Generate(16)
	require.NoError(t, err)
	assert.Len(t, first, 16)

	second, err := Generate(16)
	require.NoError(t, err)
	assert.NotEqual(t, first, second)
}
