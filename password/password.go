package password

import (
	"crypto/rand"
	"errors"
	"math"
	"math/big"
	"runtime"

	"github.com/alexedwards/argon2id"
)

// ErrBusy is returned by a Limiter when too many operations are in progress.
var ErrBusy = errors.New("too many concurrent password operations")

var defaultHashParams = argon2id.Params{
	Memory:      64 * 1024,
	Iterations:  4,
	Parallelism: parallelism(runtime.NumCPU()),
	SaltLength:  16,
	KeyLength:   32,
}

// parallelism converts a CPU count to the argon2id degree of parallelism,
// which is a uint8 and must not be zero.
func parallelism(cpus int) uint8 {
	return uint8(max(1, min(cpus, math.MaxUint8))) //nolint:gosec // clamped to the uint8 range
}

func Hash(plain string) (string, error) {
	return argon2id.CreateHash(plain, &defaultHashParams)
}

func Verify(hashedPassword, plain string) (bool, error) {
	return argon2id.ComparePasswordAndHash(plain, hashedPassword)
}

const generatedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// NeedsRehash reports whether hash should be replaced with a new Hash after a
// successful login: it is not argon2id, or its memory or iterations are below
// the current defaults. Parallelism is ignored because the default follows the
// CPU count, so a different host would otherwise rehash on every login.
func NeedsRehash(hash string) bool {
	params, _, _, err := argon2id.DecodeHash(hash)
	if err != nil {
		return true
	}
	return params.Memory < defaultHashParams.Memory || params.Iterations < defaultHashParams.Iterations
}

// Limiter caps concurrent hash operations, each of which uses tens of
// megabytes, so a burst of logins cannot exhaust memory.
type Limiter struct {
	slots chan struct{}
}

// NewLimiter returns a Limiter allowing maxConcurrent operations at once.
func NewLimiter(maxConcurrent int) *Limiter {
	return &Limiter{slots: make(chan struct{}, max(1, maxConcurrent))}
}

func (l *Limiter) acquire() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *Limiter) release() {
	<-l.slots
}

// Hash is Hash, or ErrBusy if the limit has been reached.
func (l *Limiter) Hash(plain string) (string, error) {
	if !l.acquire() {
		return "", ErrBusy
	}
	defer l.release()
	return Hash(plain)
}

// Verify is Verify, or ErrBusy if the limit has been reached.
func (l *Limiter) Verify(hashedPassword, plain string) (bool, error) {
	if !l.acquire() {
		return false, ErrBusy
	}
	defer l.release()
	return Verify(hashedPassword, plain)
}

// Generate returns length random alphanumeric characters.
func Generate(length int) (string, error) {
	out := make([]byte, length)
	charCount := big.NewInt(int64(len(generatedChars)))
	for i := range out {
		n, err := rand.Int(rand.Reader, charCount)
		if err != nil {
			return "", err
		}
		out[i] = generatedChars[n.Int64()]
	}
	return string(out), nil
}

// GenerateAPIKey returns prefix + 32 random alphanumeric characters.
func GenerateAPIKey(prefix string) (string, error) {
	key, err := Generate(32)
	if err != nil {
		return "", err
	}
	return prefix + key, nil
}
