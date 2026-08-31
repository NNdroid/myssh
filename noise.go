package myssh

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ============================================================================
// Standard Noise_NK handshake: Noise_NK_25519_ChaChaPoly_BLAKE2s
//
// This implements the SAME handshake the udp_custom server uses
// (see the udp_custom repo's noise.go). The udp_custom tunnel
// (tunnel_udp_custom.go) drives ClientNK / Finish so it can talk to a stock
// udp_custom server. Message layout, transcript hashing order, key derivation
// and Split() follow the Noise Protocol Framework (revision 34) exactly.
//
// NK pattern (one round trip; the responder's static key is known out of
// band — the server's privkey, published to clients as the Noise public key):
//
//	-> e, es   (client msg1: ephemeral + DH with the server's static key)
//	<- e, ee   (server msg2: ephemeral + DH between the two ephemerals)
//
// Both sides then Split() into k1 (client -> server) and k2 (server -> client).
//
// DOCUMENTED DEVIATION (transport phase only): instead of the spec's
// monotonically increasing internal nonce, the AEAD nonce is derived from the
// frame Seq (see seqNonce). This is the QUIC/TLS record-protection pattern and
// is what lets retransmitted frames (byte-identical) open twice. Keys, cipher,
// transcript and AAD are otherwise unchanged.
// ============================================================================

const (
	// 33 bytes, i.e. longer than BLAKE2s' 32-byte hash output, so the spec
	// requires h = HASH(protocol_name) rather than the name itself (names
	// shorter than the hash length are zero-padded instead).
	noiseProtocolName = "Noise_NK_25519_ChaChaPoly_BLAKE2s"

	// e (32) + AEAD tag over the (empty) payload (16).
	noiseMsg1Size = 32 + 16
	noiseMsg2Size = 32 + 16
)

// NoiseKeyPair represents a Curve25519 public/private keypair
type NoiseKeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// GenerateNoiseKeyPair generates a random Curve25519 keypair
func GenerateNoiseKeyPair() (*NoiseKeyPair, error) {
	var kp NoiseKeyPair
	if _, err := rand.Read(kp.PrivateKey[:]); err != nil {
		return nil, err
	}
	// Clamp private key
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	pub, err := curve25519.X25519(kp.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.PublicKey[:], pub)
	return &kp, nil
}

// ParseNoiseKey parses a 32-byte key from hex or base64 string
func ParseNoiseKey(s string) ([32]byte, error) {
	var key [32]byte
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		b, err := hex.DecodeString(s)
		if err == nil && len(b) == 32 {
			copy(key[:], b)
			return key, nil
		}
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil && len(b) == 32 {
		copy(key[:], b)
		return key, nil
	}
	b, err = base64.RawStdEncoding.DecodeString(s)
	if err == nil && len(b) == 32 {
		copy(key[:], b)
		return key, nil
	}
	return key, fmt.Errorf("invalid key format: %s (expected 64 hex chars or 32-byte base64)", s)
}

// FormatNoiseKey formats a 32-byte key to hex and base64
func FormatNoiseKey(key [32]byte) (hexStr, b64Str string) {
	return hex.EncodeToString(key[:]), base64.StdEncoding.EncodeToString(key[:])
}

func blake2sHash() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

// --- standard Noise SymmetricState (spec §5.1) ------------------------------

type symmetricState struct {
	ck   [32]byte
	h    [32]byte
	aead cipher.AEAD // nil until InitializeKey
	n    uint64      // reset to 0 by every InitializeKey
}

// newSymmetricState implements InitializeSymmetric(protocol_name):
//
//	if len(protocol_name) <= HASHLEN: h = protocol_name zero-padded to HASHLEN
//	else:                            h = HASH(protocol_name)
//
// and ck = h.
func newSymmetricState() *symmetricState {
	var h [32]byte
	if len(noiseProtocolName) <= len(h) {
		copy(h[:], noiseProtocolName)
	} else {
		hh := blake2sHash()
		hh.Write([]byte(noiseProtocolName))
		copy(h[:], hh.Sum(nil))
	}
	s := &symmetricState{ck: h, h: h}
	// The spec initialises with h = protocol_name and then immediately
	// MixHash(prologue). Our prologue is empty, but the MixHash still runs and
	// hashes h once — skipping it silently diverges from a conformant
	// implementation. MixHash only advances h; ck stays as it was.
	s.mixHash(nil)
	return s
}

// nkInit builds the NK SymmetricState:
//
//	h  = HASH(protocol_name)      (name is 33 bytes, longer than the hash)
//	h  = HASH(h || prologue)      (prologue is empty for us)
//	h  = HASH(h || rs)            (responder's static key is a pre-message)
//	ck = HASH(protocol_name)      (unchanged by MixHash)
//
// Both peers must run all three hashing steps — the pre-message is what binds
// the handshake to the server's long-term key.
func nkInit(responderStaticPub []byte) *symmetricState {
	s := newSymmetricState()
	s.mixHash(responderStaticPub)
	return s
}

func (s *symmetricState) mixHash(data []byte) {
	h := blake2sHash()
	h.Write(s.h[:])
	h.Write(data)
	sum := h.Sum(nil)
	copy(s.h[:], sum)
}

// MixKey: HKDF(ck, ikm) → new ck + key (nonce resets to 0).
func (s *symmetricState) mixKey(ikm []byte) {
	kdf := hkdf.New(blake2sHash, ikm, s.ck[:], nil)
	out := make([]byte, 64)
	if _, err := io.ReadFull(kdf, out); err != nil {
		panic("noise: hkdf failed: " + err.Error())
	}
	copy(s.ck[:], out[:32])
	var key [32]byte
	copy(key[:], out[32:])
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic("noise: chacha20poly1305 failed: " + err.Error())
	}
	s.aead = aead
	s.n = 0
}

func (s *symmetricState) handshakeNonce() []byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], s.n)
	return nonce[:]
}

// EncryptAndHash: ENCRYPT(k, n, ad=h, plaintext) then MixHash(ciphertext).
func (s *symmetricState) encryptAndHash(plaintext []byte) []byte {
	if s.aead == nil {
		out := append([]byte(nil), plaintext...)
		s.mixHash(out)
		return out
	}
	ct := s.aead.Seal(nil, s.handshakeNonce(), plaintext, s.h[:])
	s.n++
	s.mixHash(ct)
	return ct
}

// DecryptAndHash: DECRYPT(k, n, ad=h, ciphertext) then MixHash(ciphertext).
func (s *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	if s.aead == nil {
		s.mixHash(ciphertext)
		return ciphertext, nil
	}
	pt, err := s.aead.Open(nil, s.handshakeNonce(), ciphertext, s.h[:])
	if err != nil {
		return nil, err
	}
	s.n++
	s.mixHash(ciphertext)
	return pt, nil
}

// Split: HKDF(ck, empty) → k1 (initiator -> responder), k2 (responder -> initiator).
func (s *symmetricState) split() (k1, k2 []byte) {
	kdf := hkdf.New(blake2sHash, nil, s.ck[:], nil)
	out := make([]byte, 64)
	if _, err := io.ReadFull(kdf, out); err != nil {
		panic("noise: hkdf failed: " + err.Error())
	}
	return out[:32], out[32:]
}

// generateEphemeral returns a clamped Curve25519 keypair (GENERATE_KEYPAIR).
func generateEphemeral() (priv, pub [32]byte, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return priv, pub, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, pub, err
	}
	copy(pub[:], p)
	return priv, pub, nil
}

// dh performs DH and rejects a degenerate (all-zero) output, as required by
// the spec ("if the output is all-zero, abort").
func dh(priv, pub []byte) ([]byte, error) {
	out, err := curve25519.X25519(priv, pub)
	if err != nil {
		return nil, err
	}
	var zero [32]byte
	if subtleEqual(out, zero[:]) {
		return nil, errors.New("noise: degenerate DH output")
	}
	return out, nil
}

func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// seqNonce derives the 12-byte AEAD nonce from the frame sequence number.
//
// Seq is unique per direction for the session's lifetime (transport keys are
// per-session, and each key has exactly one encryptor), so Seq yields a
// replay-safe nonce: retransmissions reuse the same ciphertext AND the same
// nonce, which is exactly what the receiver expects.
func seqNonce(seq uint32) [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], uint64(seq))
	return nonce
}

// noiseTagSize is the AEAD authentication tag appended to every sealed payload
// (ChaCha20-Poly1305 overhead is 16 bytes). The DNS tunnel imports it for the
// 512-byte UDP response budget.
const noiseTagSize = chacha20poly1305.Overhead

// NoiseCipherState wraps one ChaCha20-Poly1305 transport key.
type NoiseCipherState struct {
	nonce atomic.Uint64 // only used by the legacy single-arg Encrypt/Decrypt (DNS tunnel)
	aead  cipher.AEAD
}

func newNoiseCipherState(key []byte) (*NoiseCipherState, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &NoiseCipherState{aead: aead}, nil
}

// Encrypt / Decrypt (single-arg, auto-incrementing nonce) — LEGACY API used
// by the DNS tunnel (tunnel_dns_custom.go). Kept for compatibility. New udp_custom
// code MUST use EncryptWithSeq / DecryptWithSeq so retransmissions open
// correctly.
func (s *NoiseCipherState) Encrypt(plaintext []byte) []byte {
	nonceNum := s.nonce.Add(1) - 1
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], nonceNum)
	return s.aead.Seal(nil, nonce[:], plaintext, nil)
}

func (s *NoiseCipherState) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceNum := s.nonce.Add(1) - 1
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], nonceNum)
	return s.aead.Open(nil, nonce[:], ciphertext, nil)
}

// EncryptWithSeq seals plaintext under the nonce derived from seq. The caller
// must pass the same seq it puts into the frame header.
func (s *NoiseCipherState) EncryptWithSeq(seq uint32, plaintext []byte) []byte {
	nonce := seqNonce(seq)
	return s.aead.Seal(nil, nonce[:], plaintext, nil)
}

// DecryptWithSeq opens ciphertext under the nonce derived from seq. It is a
// pure function: calling it twice with the same input (a retransmitted frame)
// yields the same result and never advances hidden state.
func (s *NoiseCipherState) DecryptWithSeq(seq uint32, ciphertext []byte) ([]byte, error) {
	nonce := seqNonce(seq)
	return s.aead.Open(nil, nonce[:], ciphertext, nil)
}

// NoiseSession is the result of a completed handshake.
type NoiseSession struct {
	SendCipher *NoiseCipherState
	RecvCipher *NoiseCipherState

	// HandshakeHash is the final handshake transcript hash h — the Noise
	// channel-binding value. It can be logged or compared out of band to bind
	// this session to the handshake that produced it.
	HandshakeHash [32]byte
}

func newNoiseSession(sendKey, recvKey []byte, h [32]byte) (*NoiseSession, error) {
	sendCipher, err := newNoiseCipherState(sendKey)
	if err != nil {
		return nil, err
	}
	recvCipher, err := newNoiseCipherState(recvKey)
	if err != nil {
		return nil, err
	}
	return &NoiseSession{SendCipher: sendCipher, RecvCipher: recvCipher, HandshakeHash: h}, nil
}

// ClientNK is the initiator side of Noise_NK (the client). The server's static
// public key is known out of band.
type ClientNK struct {
	ss        *symmetricState
	ePriv     [32]byte
	ePub      [32]byte
	serverPub [32]byte
	msg1      []byte
	finished  bool
}

// NewClientNK starts the handshake: it generates the ephemeral keypair and
// processes the "e, es" tokens of message 1.
func NewClientNK(serverPub [32]byte) (*ClientNK, error) {
	c := &ClientNK{ss: nkInit(serverPub[:]), serverPub: serverPub}
	priv, pub, err := generateEphemeral()
	if err != nil {
		return nil, err
	}
	c.ePriv, c.ePub = priv, pub

	// -> e
	c.ss.mixHash(c.ePub[:])
	// -> es
	shared, err := dh(c.ePriv[:], serverPub[:])
	if err != nil {
		return nil, fmt.Errorf("noise: es: %w", err)
	}
	c.ss.mixKey(shared)
	return c, nil
}

// Message1 returns the 48-byte handshake message to send as the Noise part of
// the SYN payload (32B ephemeral + 16B AEAD tag over the empty payload).
func (c *ClientNK) Message1() ([]byte, error) {
	if c.msg1 == nil {
		tag := c.ss.encryptAndHash(nil)
		out := make([]byte, 0, noiseMsg1Size)
		out = append(out, c.ePub[:]...)
		out = append(out, tag...)
		if len(out) != noiseMsg1Size {
			return nil, fmt.Errorf("noise: unexpected msg1 size %d", len(out))
		}
		c.msg1 = out
	}
	return append([]byte(nil), c.msg1...), nil
}

// Finish processes msg2 ("e, ee"), verifies it, and returns the transport
// session. It must be called exactly once, with the ack payload the server
// sent in reply.
func (c *ClientNK) Finish(msg2 []byte) (*NoiseSession, error) {
	if c.finished {
		return nil, errors.New("noise: handshake already finished")
	}
	if len(msg2) != noiseMsg2Size {
		return nil, fmt.Errorf("noise: msg2 is %d bytes, want %d", len(msg2), noiseMsg2Size)
	}
	// <- e
	c.ss.mixHash(msg2[:32])
	// <- ee
	shared, err := dh(c.ePriv[:], msg2[:32])
	if err != nil {
		return nil, fmt.Errorf("noise: ee: %w", err)
	}
	c.ss.mixKey(shared)
	// payload (empty) — verifies the transcript up to here
	if _, err := c.ss.decryptAndHash(msg2[32:]); err != nil {
		return nil, fmt.Errorf("noise: msg2 authentication failed: %w", err)
	}
	k1, k2 := c.ss.split()
	sess, err := newNoiseSession(k1, k2, c.ss.h) // initiator: send k1, recv k2
	if err != nil {
		return nil, err
	}
	c.finished = true
	return sess, nil
}

// NewServerNoiseSession is the responder side of Noise_NK. It consumes the
// client's message 1 and returns the established session plus the 48-byte
// message 2 that must be delivered to the client (carried in the handshake
// ACK). myssh is client-only for udp_custom, but this is provided for interop
// tests and parity with the canonical server.
func NewServerNoiseSession(serverPrivkey [32]byte, msg1 []byte) (*NoiseSession, []byte, error) {
	if len(msg1) != noiseMsg1Size {
		return nil, nil, fmt.Errorf("noise: msg1 is %d bytes, want %d", len(msg1), noiseMsg1Size)
	}
	serverPub, err := curve25519.X25519(serverPrivkey[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	ss := nkInit(serverPub)

	// -> e
	ss.mixHash(msg1[:32])
	// -> es
	shared, err := dh(serverPrivkey[:], msg1[:32])
	if err != nil {
		return nil, nil, fmt.Errorf("noise: es: %w", err)
	}
	ss.mixKey(shared)
	if _, err := ss.decryptAndHash(msg1[32:]); err != nil {
		return nil, nil, fmt.Errorf("noise: msg1 authentication failed: %w", err)
	}

	// <- e
	ePriv, ePub, err := generateEphemeral()
	if err != nil {
		return nil, nil, err
	}
	ss.mixHash(ePub[:])
	// <- ee
	shared, err = dh(ePriv[:], msg1[:32])
	if err != nil {
		return nil, nil, fmt.Errorf("noise: ee: %w", err)
	}
	ss.mixKey(shared)

	tag := ss.encryptAndHash(nil)
	msg2 := make([]byte, 0, noiseMsg2Size)
	msg2 = append(msg2, ePub[:]...)
	msg2 = append(msg2, tag...)

	k1, k2 := ss.split()
	sess, err := newNoiseSession(k2, k1, ss.h) // responder: send k2, recv k1
	if err != nil {
		return nil, nil, err
	}
	return sess, msg2, nil
}

// ============================================================================
// Legacy Noise_NK (custom KDF with a protocol-domain salt) — used ONLY by the
// DNS tunnel (tunnel_dns_custom.go). It does NOT interoperate with the udp_custom
// server and must not be used for udp_custom tunnels.
// ============================================================================

// NewClientNoiseSession initiates Noise_NK handshake against server public key
// with the DNS-tunnel protocol domain salt.
func NewClientNoiseSession(serverPubkey [32]byte) (*NoiseSession, []byte, error) {
	return NewClientNoiseSessionForProto(serverPubkey, "dns_custom_noise_v1")
}

// NewClientNoiseSessionForProto initiates Noise_NK handshake with specific
// protocol domain salt (legacy DNS-tunnel handshake).
func NewClientNoiseSessionForProto(serverPubkey [32]byte, protoDomain string) (*NoiseSession, []byte, error) {
	var ePriv [32]byte
	if _, err := rand.Read(ePriv[:]); err != nil {
		return nil, nil, err
	}
	ePriv[0] &= 248
	ePriv[31] &= 127
	ePriv[31] |= 64

	ePub, err := curve25519.X25519(ePriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	dh, err := curve25519.X25519(ePriv[:], serverPubkey[:])
	if err != nil {
		return nil, nil, err
	}

	kdf := hkdf.New(blake2sHash, dh, serverPubkey[:], []byte(protoDomain))
	kC2S := make([]byte, 32)
	kS2C := make([]byte, 32)
	if _, err := io.ReadFull(kdf, kC2S); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(kdf, kS2C); err != nil {
		return nil, nil, err
	}

	sendCipher, err := newNoiseCipherState(kC2S)
	if err != nil {
		return nil, nil, err
	}
	recvCipher, err := newNoiseCipherState(kS2C)
	if err != nil {
		return nil, nil, err
	}

	return &NoiseSession{SendCipher: sendCipher, RecvCipher: recvCipher}, ePub, nil
}

// NewServerNoiseSessionForProto derives keys on server side using server static
// private key and client ephemeral public key (legacy DNS-tunnel handshake).
func NewServerNoiseSessionForProto(serverPrivkey [32]byte, clientEPub []byte, protoDomain string) (*NoiseSession, error) {
	if len(clientEPub) != 32 {
		return nil, errors.New("invalid client ephemeral pubkey length")
	}
	serverPub, err := curve25519.X25519(serverPrivkey[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	dh, err := curve25519.X25519(serverPrivkey[:], clientEPub)
	if err != nil {
		return nil, err
	}

	kdf := hkdf.New(blake2sHash, dh, serverPub, []byte(protoDomain))
	kC2S := make([]byte, 32)
	kS2C := make([]byte, 32)
	if _, err := io.ReadFull(kdf, kC2S); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(kdf, kS2C); err != nil {
		return nil, err
	}

	recvCipher, err := newNoiseCipherState(kC2S)
	if err != nil {
		return nil, err
	}
	sendCipher, err := newNoiseCipherState(kS2C)
	if err != nil {
		return nil, err
	}

	return &NoiseSession{SendCipher: sendCipher, RecvCipher: recvCipher}, nil
}
