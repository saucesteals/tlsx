package tls

import (
	"crypto"
	standard "crypto/tls"
	"errors"
	"hash"
	"os"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/saucesteals/tlsx/internal/fips140tls"
)

// ClientCompatibility supplies optional per-connection client wire adaptations.
// Callbacks must be deterministic for repeated serialization of the same hello.
// Config.Compatibility creates a fresh instance for each handshake.
// The callbacks are trusted protocol code: they must preserve negotiation,
// transcript and length invariants. Browser-specific policy belongs to the caller.
type ClientCompatibility struct {
	Hello ClientHelloParameters
	// PeerPublicKey may select an authenticated TLS 1.3 signing key after native
	// chain/hostname verification. Nil keys retain the leaf key. The caller must
	// authenticate any replacement and validate its negotiated signature scheme;
	// native key-type and CertificateVerify verification remain.
	PeerPublicKey func(ConnectionState, SignatureScheme, time.Time) (crypto.PublicKey, error)
	// LoadSession restores and validates connection-local metadata after native
	// cached-certificate checks. An error discards the session, forcing a full handshake.
	LoadSession func(*SessionState, ConnectionState, time.Time) error
	// StoreSession appends namespaced metadata to Extra before caching a ticket.
	StoreSession func(*SessionState)
	// RecordSizeLimit returns the negotiated peer's maximum encrypted plaintext
	// size (including the TLS 1.3 content type). Zero keeps the native limit.
	// It must be concurrency-safe. Record-limited renegotiation is not supported.
	RecordSizeLimit func(version uint16) int

	keys map[CurveID]*keySharePrivateKeys

	// ClientHello transforms native serialization before binder/ECH/transcript use.
	// It must preserve key material and keep PSK last. Nil leaves serialization intact.
	ClientHello func(native []byte, inner bool) ([]byte, error)
	// CertificateMessageTypes permits alternate TLS 1.3 certificate encodings to
	// use the native certificate receive limit before DecodeHandshake runs.
	CertificateMessageTypes []uint8
	// DecodeHandshake adapts a copy for parsing; the original bytes are hashed.
	// Enforce certificateLimit when decompressing. Errors may wrap AlertError.
	DecodeHandshake func(message []byte, certificateLimit int) ([]byte, error)
	// ClientFlight returns one complete message after server Finished verification,
	// before client authentication and Finished. Nil or an empty result sends none.
	ClientFlight func(alpn string) ([]byte, error)
}

// ClientHelloParameters contains negotiation preferences, never private keys.
type ClientHelloParameters struct {
	CipherSuites                []uint16
	Groups                      []CurveID
	SignatureSchemes            []SignatureScheme
	CertificateSignatureSchemes []SignatureScheme
	// KeyShares selects the exact ordered set of real initial shares.
	KeyShares []CurveID
	// ReuseHybridKey shares a hybrid's classical component with its fallback.
	// False generates independent keys for every explicitly requested group.
	ReuseHybridKey  bool
	TicketSupported bool
	PSKModes        []byte
}

func (m *clientHelloMsg) configureCompatibility(config *Config, compatibility *ClientCompatibility, keys *keySharePrivateKeys) error {
	if compatibility == nil {
		return nil
	}
	if fips140tls.Required() {
		return errors.New("tls: wire profiles are unavailable in FIPS mode")
	}
	p := compatibility.Hello
	grease := func(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v) == byte(v>>8) }
	for _, suite := range p.CipherSuites {
		if !grease(suite) && cipherSuiteByID(suite) == nil && cipherSuiteTLS13ByID(suite) == nil {
			return errors.New("tls: unsupported compatibility cipher")
		}
	}
	allowed := config.curvePreferences(VersionTLS13)
	for _, group := range p.Groups {
		if !grease(uint16(group)) && !slices.Contains(allowed, group) {
			return errors.New("tls: unsupported compatibility group")
		}
	}
	if len(p.KeyShares) == 0 {
		return errors.New("tls: missing compatibility key shares")
	}
	preferred := p.KeyShares[0]
	if !slices.Contains(p.Groups, preferred) || !slices.Contains(allowed, preferred) {
		return errors.New("tls: unsupported compatibility key share")
	}
	if keys != nil {
		original := m.keyShares
		m.keyShares = nil
		compatibility.keys = make(map[CurveID]*keySharePrivateKeys)
		for _, group := range p.KeyShares {
			if !slices.Contains(p.Groups, group) || !slices.Contains(allowed, group) || compatibility.keys[group] != nil {
				return errors.New("tls: invalid compatibility key shares")
			}
			if i := slices.IndexFunc(original, func(s keyShare) bool { return s.group == group }); i >= 0 && (i == 0 || p.ReuseHybridKey) {
				m.keyShares = append(m.keyShares, original[i])
				compatibility.keys[group] = keys
				continue
			}
			ke, err := keyExchangeForCurveID(group)
			if err != nil {
				return err
			}
			private, shares, err := ke.keyShares(config.rand())
			if err != nil {
				return err
			}
			m.keyShares = append(m.keyShares, shares[0])
			compatibility.keys[group] = private
		}
	}
	m.compatibility = compatibility
	m.cipherSuites, m.supportedCurves = p.CipherSuites, p.Groups
	m.supportedSignatureAlgorithms, m.supportedSignatureAlgorithmsCert = p.SignatureSchemes, p.CertificateSignatureSchemes
	m.ticketSupported, m.pskModes = p.TicketSupported && !config.SessionTicketsDisabled, p.PSKModes
	return nil
}

type compatibilityMessage []byte

func (m compatibilityMessage) marshal() ([]byte, error) {
	if len(m) < 4 || int(m[1])<<16|int(m[2])<<8|int(m[3]) != len(m)-4 {
		return nil, errors.New("tls: invalid compatibility handshake")
	}
	return m, nil
}
func (compatibilityMessage) unmarshal([]byte) bool { return false }

// marshalCompatibility leaves native extension serialization untouched. ECH inner
// hellos omit legacy fields but keep extensions inline: arbitrary profile ordering
// cannot use the native contiguous outer-extension compression block.
func (m *clientHelloMsg) marshalCompatibility(inner bool) ([]byte, error) {
	hello := *m
	hello.compatibility = nil
	if inner {
		hello.sessionId = nil
		hello.supportedPoints = nil
		hello.ticketSupported = false
		hello.secureRenegotiationSupported = false
		hello.extendedMasterSecret = false
	}
	raw, err := hello.marshalMsg(false)
	if err != nil || m.compatibility.ClientHello == nil {
		return raw, err
	}
	return m.compatibility.ClientHello(raw, inner)
}

func (hs *clientHandshakeStateTLS13) sendCompatibilityFlight() error {
	c := hs.c
	if p := c.compatibility; p != nil && p.ClientFlight != nil {
		data, err := p.ClientFlight(c.clientProtocol)
		if err != nil {
			return err
		}
		if len(data) > 0 {
			if _, err := c.writeHandshakeRecord(compatibilityMessage(data), hs.transcript); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Conn) compatibilityKeyShare(fallback CurveID) CurveID {
	if c.compatibility != nil {
		if shares := c.compatibility.Hello.KeyShares; len(shares) > 0 {
			return shares[0]
		}
	}
	return fallback
}

func (hs *clientHandshakeStateTLS13) compatibilityKeys() *keySharePrivateKeys {
	if p := hs.c.compatibility; p != nil {
		if keys := p.keys[hs.serverHello.serverShare.group]; keys != nil {
			return keys
		}
	}
	return hs.keyShareKeys
}

func (c *Conn) compatibilityPeerKey(algorithm SignatureScheme) (crypto.PublicKey, error) {
	key := c.peerCertificates[0].PublicKey
	if p := c.compatibility; p != nil && p.PeerPublicKey != nil {
		replacement, err := p.PeerPublicKey(c.connectionStateLocked(), algorithm, c.config.time())
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return nil, err
		}
		if replacement != nil {
			return replacement, nil
		}
	}
	if p := c.compatibility; p != nil && !isSupportedSignatureAlgorithm(algorithm, p.Hello.SignatureSchemes) {
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("tls: certificate used with unadvertised signature algorithm")
	}
	return key, nil
}

func (c *Conn) loadCompatibilitySession(s *SessionState) bool {
	if p := c.compatibility; p != nil && p.LoadSession != nil {
		state := ConnectionState{Version: s.version, DidResume: true, CipherSuite: s.cipherSuite,
			PeerCertificates: s.peerCertificates, VerifiedChains: s.verifiedChains}
		if err := p.LoadSession(s, state, c.config.time()); err != nil {
			c.config.ClientSessionCache.Put(c.clientSessionCacheKey(), nil)
			return false
		}
	}
	return true
}

func (c *Conn) storeCompatibilitySession(s *SessionState) *SessionState {
	if p := c.compatibility; p != nil && p.StoreSession != nil {
		p.StoreSession(s)
	}
	return s
}

func (c *Conn) compatibilityRecordSize(typ recordType) (int, error) {
	size := c.maxPayloadSizeForWrite(typ)
	if p := c.compatibility; p != nil && p.RecordSizeLimit != nil && c.out.cipher != nil {
		limit := p.RecordSizeLimit(c.vers)
		if limit != 0 {
			if limit < 64 || limit > maxPlaintext+1 {
				return 0, errors.New("tls: invalid compatibility record limit")
			}
			if c.vers == VersionTLS13 {
				limit--
			}
			size = min(size, limit)
		}
	}
	return size, nil
}

func (c *Conn) initCompatibility() error {
	if c.config.Compatibility == nil {
		return nil
	}
	if c.handshakes > 0 && c.compatibility != nil && c.compatibility.RecordSizeLimit != nil {
		return errors.New("tls: record-limited compatibility does not support renegotiation")
	}
	var err error
	c.compatibility, err = c.config.Compatibility()
	return err
}

func (c *Conn) compatibilityCertificateMessage(typ uint8) bool {
	p := c.compatibility
	return c.isClient && c.vers == VersionTLS13 && p != nil && slices.Contains(p.CertificateMessageTypes, typ)
}

func (c *Conn) decodeCompatibilityHandshake(data []byte) ([]byte, error) {
	if p := c.compatibility; c.isClient && p != nil && p.DecodeHandshake != nil {
		var err error
		data, err = p.DecodeHandshake(append([]byte(nil), data...), maxHandshakeCertificateMsg)
		if err != nil {
			code := AlertError(alertDecodeError)
			errors.As(err, &code)
			c.sendAlert(alert(code))
			return nil, c.in.setErrorLocked(err)
		}
		if len(data) < 4 {
			return nil, c.in.setErrorLocked(c.sendAlert(alertDecodeError))
		}
	}
	return data, nil
}

// Standard returns the Go 1.27.2 connection state, including its key exporter.
// Both structs come from the same upstream definition. No reflection or private
// symbol lookup is used. Keep this boundary in sync when updating the fork.
func (s ConnectionState) Standard() standard.ConnectionState {
	return *(*standard.ConnectionState)(unsafe.Pointer(&s))
}

// A changed state size must fail compilation rather than silently truncate.
var _ [unsafe.Sizeof(ConnectionState{}) - unsafe.Sizeof(standard.ConnectionState{})]byte
var _ [unsafe.Sizeof(standard.ConnectionState{}) - unsafe.Sizeof(ConnectionState{})]byte

// godebugSetting reads TLS settings without depending on runtime internals.
// It does not reproduce runtime metrics or build-time GODEBUG defaults.
type godebugSetting string

func (s godebugSetting) Value() string {
	value := ""
	for _, field := range strings.Split(os.Getenv("GODEBUG"), ",") {
		if k, v, ok := strings.Cut(field, "="); ok && k == string(s) {
			value = v
		}
	}
	return value
}

func (godebugSetting) IncNonDefault() {}

// tls12PRF implements the TLS 1.2 PRF defined in RFC 5246, Section 5.
func tls12PRF(newHash func() hash.Hash, secret []byte, label string, seed []byte, keyLen int) []byte {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)
	result := make([]byte, keyLen)
	pHash(result, secret, labelAndSeed, newHash)
	return result
}

// tls12MasterSecret derives the extended master secret defined in RFC 7627.
func tls12MasterSecret(newHash func() hash.Hash, preMasterSecret, transcript []byte) []byte {
	return tls12PRF(newHash, preMasterSecret, extendedMasterSecretLabel, transcript, masterSecretLength)
}

// compatibilityCipherSuite adds an explicit-only combination of native TLS 1.2
// primitives without changing upstream preference lists or default suites.
func compatibilityCipherSuite(id uint16) *cipherSuite {
	if id == 0xc008 {
		return &cipherSuite{0xc008, 24, 20, 8, ecdheECDSAKA,
			suiteECDHE | suiteECSign, cipher3DES, macSHA1, nil}
	}
	return nil
}
