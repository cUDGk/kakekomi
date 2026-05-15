package kakekomi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// Server-side PoW (SPEC F-06, HARDENING §L3.2 + §L4).
//
// Goal: rate-limit /submit without requiring browser JavaScript.
// Approach:
//   1. GET /submit issues a "challenge" token = HMAC(pow_key, nonce || timestamp).
//   2. POST /submit returns the token.
//   3. Server verifies token freshness + HMAC.
//   4. Server then performs an N-iteration SHA-256 hash chain BEFORE accepting
//      the submission. The hash chain cost is paid by the SERVER, not the
//      client — this is intentional. It throttles per-process, which combined
//      with Tor's circuit-establishment cost and IntroDoSDefense makes the
//      attack budget non-trivial.
//
// Token format: hex( ts(8B BE) || rand(16B) || HMAC-SHA256(key, ts||rand)[:16] )

const (
	powTokenLifetime = 5 * time.Minute
	powHashChainCost = 1 << 16 // ~65k SHA-256 iterations ~ a few ms server-side
)

func IssuePoWToken(key []byte) string {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().Unix()))
	var nonce [16]byte
	if _, err := readRandom(nonce[:]); err != nil {
		// caller will see token verify failure if RNG is dead
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(ts[:])
	mac.Write(nonce[:])
	sum := mac.Sum(nil)[:16]

	out := make([]byte, 0, 40)
	out = append(out, ts[:]...)
	out = append(out, nonce[:]...)
	out = append(out, sum...)
	return hex.EncodeToString(out)
}

func VerifyPoWToken(key []byte, token string) error {
	raw, err := hex.DecodeString(strings.TrimSpace(token))
	if err != nil || len(raw) != 40 {
		return errBadPoWToken
	}
	ts := raw[0:8]
	nonce := raw[8:24]
	got := raw[24:40]

	mac := hmac.New(sha256.New, key)
	mac.Write(ts)
	mac.Write(nonce)
	want := mac.Sum(nil)[:16]
	if !hmac.Equal(got, want) {
		return errBadPoWToken
	}
	tsVal := int64(binary.BigEndian.Uint64(ts))
	age := time.Since(time.Unix(tsVal, 0))
	if age < 0 || age > powTokenLifetime {
		return errExpiredPoWToken
	}
	return nil
}

// PoWWork performs the SHA-256 hash chain. Returns nothing — its purpose is
// purely to consume server CPU time before accepting a submission.
func PoWWork(token string, cost int) {
	if cost <= 0 {
		cost = powHashChainCost
	}
	h := sha256.New()
	h.Write([]byte(token))
	buf := h.Sum(nil)
	for i := 0; i < cost; i++ {
		h.Reset()
		h.Write(buf)
		buf = h.Sum(buf[:0])
	}
}

var (
	errBadPoWToken     = errors.New("invalid PoW token")
	errExpiredPoWToken = errors.New("PoW token expired")
)
