// Package boring preserves upstream guards for tlsx's non-BoringCrypto build.
package boring

// Enabled is false because tlsx does not use Go's internal BoringCrypto backend.
const Enabled = false

// Unreachable is a no-op without BoringCrypto, as in upstream Go.
func Unreachable() {}
