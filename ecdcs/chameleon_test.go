package ecdcs

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestSignatureVerify(t *testing.T) {
	curve := elliptic.P256()
	sk, _ := GenerateKey(curve, rand.Reader)
	r1, sign, _ := sk.Signature(curve, "test")
	r2 := sk.ReSignature(curve, "test", "test2", r1)
	pk, _ := sk.ExportPublicKey(curve)

	t.Log(sk.ToHexString())
	t.Log(hex.EncodeToString(r1))

	result, _ := pk.Verify(curve, "test2", sign, r2)
	if !result {
		t.Error("Chameleon signature & verify failed.")
	}
}
