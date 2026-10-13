// Package testenv provides the helpers used by the portable upstream tests.
package testenv

import (
	"os"
	"testing"
)

// SetGODEBUG adds settings for the test and restores the environment afterward.
func SetGODEBUG(t testing.TB, value string) {
	t.Helper()
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+","+value)
}

// MustHaveExternalNetwork skips external-network tests in the portable audit.
// Unlike upstream's helper, it always skips, preserving tlsx's offline policy.
func MustHaveExternalNetwork(t testing.TB) {
	t.Helper()
	t.Skip("external network excluded from portable upstream audit")
}
