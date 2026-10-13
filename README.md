# tlsx

Go’s `crypto/tls` with small, reusable hooks for browser impersonation. [Mimic](https://github.com/saucesteals/mimic) supplies the browser profiles; tlsx handles TLS.

## Maintenance

Keep one compatibility commit on top of the upstream TLS source. When updating Go, import the new upstream version, replay that commit, and run the upstream TLS tests and Mimic’s compatibility checks before tagging a release. Keep browser-specific behavior in Mimic.
