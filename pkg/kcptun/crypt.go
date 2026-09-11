// Package kcptun contains the kcptun wire-protocol helpers vendored from
// the archived github.com/xtaci/kcptun repository (MIT licensed, via the
// dumbybumby/kcptun-archive backup): cipher selection, session-level
// Snappy compaction and SMUX configuration. Only the pieces the embedded
// client needs are kept; everything else (CLI wiring, multiport, qpp)
// was left behind in the archive.
package kcptun

import (
	"log"

	kcp "github.com/xtaci/kcp-go/v5"
)

// cryptMethod maps cipher names to their constructor functions and required key sizes.
type cryptMethod struct {
	keySize int // required key size (0 means use full key)
	build   func(key []byte) (kcp.BlockCrypt, error)
}

// cryptMethods is a lookup table for supported encryption methods.
// Using a map simplifies the code and makes adding new ciphers easier.
var cryptMethods = map[string]cryptMethod{
	"null":        {0, func(key []byte) (kcp.BlockCrypt, error) { return nil, nil }},
	"sm4":         {16, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewSM4BlockCrypt(key) }},
	"tea":         {16, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewTEABlockCrypt(key) }},
	"xor":         {0, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewSimpleXORBlockCrypt(key) }},
	"none":        {0, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewNoneBlockCrypt(key) }},
	"aes-128":     {16, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewAESBlockCrypt(key) }},
	"aes-192":     {24, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewAESBlockCrypt(key) }},
	"blowfish":    {0, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewBlowfishBlockCrypt(key) }},
	"twofish":     {0, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewTwofishBlockCrypt(key) }},
	"cast5":       {16, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewCast5BlockCrypt(key) }},
	"3des":        {24, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewTripleDESBlockCrypt(key) }},
	"xtea":        {16, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewXTEABlockCrypt(key) }},
	"salsa20":     {0, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewSalsa20BlockCrypt(key) }},
	"aes-128-gcm": {16, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewAESGCMCrypt(key) }},
}

// SelectBlockCrypt translates a human readable cipher name into the concrete
// kcp.BlockCrypt implementation. It also reports the effective cipher name after
// applying fallbacks so callers can log the final choice.
func SelectBlockCrypt(method string, pass []byte) (kcp.BlockCrypt, string) {
	if m, ok := cryptMethods[method]; ok {
		key := pass
		if m.keySize > 0 && len(pass) >= m.keySize {
			key = pass[:m.keySize]
		}
		block, err := m.build(key)
		if err != nil {
			log.Printf("crypt: failed to create %s cipher: %v, falling back to aes", method, err)
			block, _ = kcp.NewAESBlockCrypt(pass)
			return block, "aes"
		}
		return block, method
	}
	// Default to AES for unknown methods
	block, err := kcp.NewAESBlockCrypt(pass)
	if err != nil {
		log.Printf("crypt: failed to create default aes cipher: %v", err)
	}
	return block, "aes"
}
