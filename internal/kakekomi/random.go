package kakekomi

import "crypto/rand"

// readRandom is the single allowed RNG entry point.
// `math/rand` MUST NOT be imported (SPEC F-X11). If it is, this entire build
// is suspect — search the tree for `"math/rand"` to catch any drift.
func readRandom(b []byte) (int, error) { return rand.Read(b) }
