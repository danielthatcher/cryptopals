package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"math/big"
)

type DiffieHellman struct {
	P big.Int
	G big.Int
}

func NISTDiffieHellman() DiffieHellman {
	var p big.Int
	p.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	g := big.NewInt(2)
	d := DiffieHellman{P: p, G: *g}
	return d
}

func (d *DiffieHellman) PublicKey(a int) big.Int {
	var r big.Int
	A := big.NewInt(int64(a))
	r.Exp(&d.G, A, &d.P)
	return r
}

func (d *DiffieHellman) SharedKey(A big.Int, b int) ([]byte, []byte) {
	var B big.Int
	var S big.Int
	B.SetInt64(int64(b))
	S.Exp(&A, &B, &d.P)
	data, _ := S.GobEncode()
	x := sha256.Sum256(data)
	return x[:16], x[16:]
}

func DHEncrypt(msg []byte, S []byte) ([]byte, []byte) {
	msg = Pad(msg, len(S))
	block, _ := aes.NewCipher(S)
	iv := RandomBytes(len(S))
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(msg))
	mode.CryptBlocks(ciphertext, msg)

	return ciphertext, iv
}

func DHDecrypt(msg []byte, S []byte, iv []byte) []byte {
	block, _ := aes.NewCipher(S)
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(msg))
	mode.CryptBlocks(plaintext, msg)

	return plaintext
}
