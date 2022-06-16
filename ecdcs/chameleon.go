package ecdcs

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"reflect"
)

// Signature 变色龙签名方法, 输入消息和曲线信息, 输出随机数和签名信息
func (sk PrivateKey) Signature(curve elliptic.Curve, message []byte) (random []byte, signature []byte, err error) {
	N := curve.Params().N
	//bitSize := N.BitLen()

	// 先通过sha256来缩短消息长度, 然后再选取一个随机数进行签名
	m := sha256.Sum256(message)
	numberM := new(big.Int).SetBytes(m[:])
	numberR, err := rand.Int(rand.Reader, N)

	if err != nil {
		return
	}

	numberX := new(big.Int).SetBytes(sk.privateBytes)

	k := new(big.Int)
	k.Mul(numberX, numberR)
	k.Add(k, numberM)
	k.Mod(k, N)

	bytesK := k.Bytes()
	x, y := curve.ScalarBaseMult(bytesK)

	random = numberR.Bytes()
	signature = elliptic.Marshal(curve, x, y)

	signatureByte32 := sha256.Sum256(signature)
	signature = signatureByte32[:]

	return
}

func (sk PrivateKey) SignatureString(curve elliptic.Curve, message string) (random []byte, signature []byte, err error) {
	return sk.Signature(curve, []byte(message))
}

// ReSignature 变色龙签名更新方法, 输入消息m1和m2以及前一次是随机数r1, 输出新的签名和r2
func (sk PrivateKey) ReSignature(curve elliptic.Curve, m1, m2 string, r1 []byte) (r2 []byte) {
	N := curve.Params().N

	sha256M1 := sha256.Sum256([]byte(m1))
	sha256M2 := sha256.Sum256([]byte(m2))

	numberX := new(big.Int).SetBytes(sk.privateBytes)

	numberM1 := new(big.Int).SetBytes(sha256M1[:])
	numberM2 := new(big.Int).SetBytes(sha256M2[:])
	numberR1 := new(big.Int).SetBytes(r1)

	k := new(big.Int)
	// 为了保证xr1 + m1 = xr2 + m2
	// 计算 r2 = (x*r1 + m1 - m2) / x
	k.Mul(numberX, numberR1)
	k.Add(k, numberM1)
	k.Mod(k, N)
	k.Sub(k, numberM2)
	k.Mod(k, N)

	inverseX := new(big.Int)
	// 求逆元, 然后计算r2
	inverseX.ModInverse(numberX, N)
	k.Mul(k, inverseX)
	k.Mod(k, N)

	r2 = k.Bytes()
	return
}

// Verify 验证变色龙签名是否正确
func (pk PublicKey) Verify(curve elliptic.Curve, message []byte, signature string, random string) (result bool, err error) {
	sha256M := sha256.Sum256(message)

	x0, y0 := elliptic.Unmarshal(curve, pk.publicBytes)
	randomBytes, err := hex.DecodeString(random)

	if err != nil {
		return false, err
	}

	x0, y0 = curve.ScalarMult(x0, y0, randomBytes)

	x, y := curve.ScalarBaseMult(sha256M[:])
	x, y = curve.Add(x0, y0, x, y)

	sign0 := elliptic.Marshal(curve, x, y)
	signatureByte32 := sha256.Sum256(sign0)
	sign0 = signatureByte32[:]

	result = reflect.DeepEqual(hex.EncodeToString(sign0), signature)
	return
}
