package utils

import (
	"crypto/rand"
	"io"
	"math/big"
)

type PublicKey struct {
	E *big.Int
	N *big.Int
}

type PrivateKey struct {
	D *big.Int
}

func NewPublicKey(e, n *big.Int) *PublicKey {
	return &PublicKey{
		E: e,
		N: n,
	}
}

func NewPrivateKey(d *big.Int) *PrivateKey {
	return &PrivateKey{
		D: d,
	}
}

/* Процедура дополнения текста до блока нужного размера */
func PKCS7Padding(data *[]byte, blockSize int) {
	// расчет недостающего количество байт в блоке
	padNum := blockSize - (len(*data) % blockSize)

	// если количество 0, устанавливается значение размера блока
	if padNum == 0 {
		padNum = blockSize
	}

	// добавление необходимого количество байт со значением соответствующим этому количеству
	for i := 0; i < padNum; i++ {
		*data = append(*data, byte(padNum))
	}
}

/* Процедура удаления дополнений текста */
func PKCS7UnPadding(data *[]byte) {
	// получение значения добавленных данных (выбор последнего элемента, его значение соответствует количеству)
	padNum := (*data)[len(*data)-1]
	// удаление добавленных блоков
	*data = (*data)[0 : len(*data)-int(padNum)]
}

func GenerateKeyPair() (*PublicKey, *PrivateKey, error) {
Primes:
	p := generatePrimeNumber(byteLenght)
	q := generatePrimeNumber(byteLenght)

	subPQ := new(big.Int).Sub(p, q)
	if subPQ.Sign() < 0 {
		subPQ.Mul(subPQ, iM1)
	}
	if len(subPQ.Bytes()) < byteLenght/8 {
		goto Primes
	}

	n := new(big.Int).Mul(p, q)
	phiN := new(big.Int).Mul(new(big.Int).Sub(p, i1), new(big.Int).Sub(q, i1))
	kBytes := make([]byte, int(16))

Start:
	if _, err := io.ReadFull(rand.Reader, kBytes); err != nil {
		return nil, nil, err
	}

	// приведение к целочисленному значению
	e := new(big.Int).SetBytes(kBytes)
	e = new(big.Int).Mod(e, phiN)
	if g, _, _ := extendedGCD(phiN, e); g.Cmp(i1) != 0 {
		goto Start
	}

	gcd, d, _ := extendedGCD(e, phiN)
	if gcd.Cmp(i1) != 0 {
		goto Start
	}
	d = new(big.Int).Mod(d, phiN)

	return NewPublicKey(e, n), NewPrivateKey(d), nil
}

func (pubKey *PublicKey) ShipherBytes(M []byte) [][]byte {
	chipher := [][]byte{}
	m := [][]byte{}
	PKCS7Padding(&M, blockSize)
	for i := 0; i < len(M); i += blockSize {
		m = append(m, M[i:i+blockSize])
	}

	for _, mBytes := range m {
		mBlock := new(big.Int).SetBytes(mBytes)
		chipher = append(chipher, exp(mBlock, pubKey.E, pubKey.N).Bytes())
	}

	return chipher
}

func (privKey *PrivateKey) DeShipherBytes(chiper [][]byte, pubKey *PublicKey) []byte {
	M := []byte{}
	for _, mBytes := range chiper {
		m := new(big.Int).SetBytes(mBytes)
		dechipher := exp(m, privKey.D, pubKey.N)
		M = append(M, dechipher.Bytes()...)
	}

	PKCS7UnPadding(&M)

	return M
}
