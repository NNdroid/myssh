package myssh

import (
	"bytes"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// dnsCustomReferenceServerSession is a verbatim transcription of dns_custom's
// NewServerNoiseSession (dns_custom/noise.go). It exists so this package can
// prove wire compatibility with the dns_custom v1.2.0 server WITHOUT spawning
// the server binary: if either side's key schedule is ever touched, this test
// fails instead of the failure surfacing only in a live tunnel as an opaque
// "chacha20poly1305: message authentication failed".
//
// Keep it byte-for-byte in sync with dns_custom; do NOT refactor it to call the
// myssh helpers, because then it would no longer be an independent oracle.
func dnsCustomReferenceServerSession(t *testing.T, serverPriv [32]byte, clientEPub []byte) (recvCipher, sendCipher *NoiseCipherState) {
	t.Helper()
	serverPub, err := curve25519.X25519(serverPriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("reference: derive server pub: %v", err)
	}
	dh, err := curve25519.X25519(serverPriv[:], clientEPub)
	if err != nil {
		t.Fatalf("reference: dh: %v", err)
	}
	kdf := hkdf.New(blake2sHash, dh, serverPub, []byte("dns_custom_noise_v1"))
	kC2S := make([]byte, 32)
	kS2C := make([]byte, 32)
	if _, err := io.ReadFull(kdf, kC2S); err != nil {
		t.Fatalf("reference: read kC2S: %v", err)
	}
	if _, err := io.ReadFull(kdf, kS2C); err != nil {
		t.Fatalf("reference: read kS2C: %v", err)
	}
	recvCipher, err = newNoiseCipherState(kC2S)
	if err != nil {
		t.Fatalf("reference: recv cipher: %v", err)
	}
	sendCipher, err = newNoiseCipherState(kS2C)
	if err != nil {
		t.Fatalf("reference: send cipher: %v", err)
	}
	return recvCipher, sendCipher
}

// TestDNSNoiseInteropWithDNSCustomReference pins the DNS-tunnel Noise handshake
// (the legacy custom-KDF one, protocol domain "dns_custom_noise_v1") against an
// inline copy of the dns_custom server's key schedule, in both directions and
// with a non-monotonic sequence number (retransmission-style reuse).
//
// Verified end-to-end on 2026-08-29 against a real dns_custom v1.2.0 server
// subprocess: 31 / 300 / 1500-byte echoes round-tripped with 0 decryption
// failures in either direction.
func TestDNSNoiseInteropWithDNSCustomReference(t *testing.T) {
	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// The client only ever learns the PUBLIC key. Note that FormatNoiseKey
	// returns (hex, base64) of the SAME key — passing its second return value
	// as "the pubkey" hands the client the private key and silently breaks the
	// handshake. That mistake cost a full debugging round; hence this comment.
	client, ePub, err := NewClientNoiseSession(kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serverRecv, serverSend := dnsCustomReferenceServerSession(t, kp.PrivateKey, ePub)

	msg := []byte("hello world this is a test message of some length here 1234567890")

	// Upstream: client SendCipher -> dns_custom server RecvCipher, nonce = dataSeq.
	for _, seq := range []uint32{1, 2, 7, 65535, 1 << 20} {
		ct := client.SendCipher.EncryptWithSeq(seq, msg)
		dec, err := serverRecv.DecryptWithSeq(seq, ct)
		if err != nil {
			t.Fatalf("upstream seq=%d decrypt failed: %v", seq, err)
		}
		if !bytes.Equal(dec, msg) {
			t.Fatalf("upstream seq=%d plaintext mismatch", seq)
		}
		// A retransmission is byte-identical and must open a second time.
		if again := client.SendCipher.EncryptWithSeq(seq, msg); !bytes.Equal(again, ct) {
			t.Fatalf("upstream seq=%d retransmit ciphertext not deterministic", seq)
		}
		if _, err := serverRecv.DecryptWithSeq(seq, ct); err != nil {
			t.Fatalf("upstream seq=%d replayed frame failed to open: %v", seq, err)
		}
	}

	// Downstream: dns_custom server SendCipher -> client RecvCipher, nonce = serverSeq.
	for _, seq := range []uint32{1, 5, 4096} {
		ct := serverSend.EncryptWithSeq(seq, msg)
		dec, err := client.RecvCipher.DecryptWithSeq(seq, ct)
		if err != nil {
			t.Fatalf("downstream seq=%d decrypt failed: %v", seq, err)
		}
		if !bytes.Equal(dec, msg) {
			t.Fatalf("downstream seq=%d plaintext mismatch", seq)
		}
	}

	// The two directions must use different keys, otherwise the "interop" above
	// would pass even with a swapped/duplicated key schedule.
	if _, err := serverRecv.DecryptWithSeq(3, serverSend.EncryptWithSeq(3, msg)); err == nil {
		t.Fatal("kC2S == kS2C: the two directions share a key, key schedule is broken")
	}
}
