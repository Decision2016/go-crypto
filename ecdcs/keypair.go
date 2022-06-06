package ecdcs

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
)

type PrivateKey struct {
	privateBytes []byte
}

type PublicKey struct {
	// publicKey = ScalarBaseMult(privateKey)
	publicBytes []byte
}

var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}

// ToHexString 转换私钥信息为16进制字符串
func (sk PrivateKey) ToHexString() string {
	return hex.EncodeToString(sk.privateBytes)
}

// ToHexString 转换私钥信息为16进制字符串
func (pk PublicKey) ToHexString() string {
	return hex.EncodeToString(pk.publicBytes)
}

// FromHexString 通过16进制字符串得到私钥信息
func (sk PrivateKey) FromHexString(s string) (err error) {
	decodeBytes, err := hex.DecodeString(s)

	if err != nil {
		return
	}

	sk.privateBytes = decodeBytes
	return
}

// FromHexString 通过16进制字符串得到公钥信息
func (pk PublicKey) FromHexString(s string) (err error) {
	decodeBytes, err := hex.DecodeString(s)

	if err != nil {
		return
	}

	pk.publicBytes = decodeBytes
	return
}

/*
	ExportPublicKey 通过私钥导出得到公钥
	curve: 选取用来进行计算的曲线
	pk： 返回得到的公钥
	err: 返回错误信息
*/
func (sk PrivateKey) ExportPublicKey(curve elliptic.Curve) (pk PublicKey, err error) {

	var x *big.Int
	var y *big.Int
	priv := sk.privateBytes
	x, y = curve.ScalarBaseMult(priv)

	publicBytes := elliptic.Marshal(curve, x, y)

	pk = PublicKey{
		publicBytes: publicBytes,
	}

	return
}

func GenerateKey(curve elliptic.Curve, rand io.Reader) (sk PrivateKey, err error) {
	N := curve.Params().N
	bitSize := N.BitLen()
	byteLen := (bitSize + 7) / 8
	privateBytes := make([]byte, byteLen)

	for {
		_, err = io.ReadFull(rand, privateBytes)
		privateBytes[0] &= mask[bitSize%8]
		privateBytes[1] ^= 0x42

		if err != nil {
			return
		}

		if new(big.Int).SetBytes(privateBytes).Cmp(N) >= 0 {
			continue
		}

		break
	}

	sk = PrivateKey{
		privateBytes: privateBytes,
	}

	return
}

func DefaultGenerateKey() (sk PrivateKey, err error) {
	sk, err = GenerateKey(elliptic.P384(), rand.Reader)
	return
}
