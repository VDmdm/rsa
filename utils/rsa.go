package utils

import (
	"crypto/rand"
	"io"
	"math/big"
)

var (
	bitLenght     = 2048
	blockSize     = bitLenght - 1
	minDiffLenght = bitLenght / 10
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

// Процедура генерации ключевой пары
func GenerateKeyPair() (*PublicKey, *PrivateKey, error) {
Primes:
	// генерируем простые числа p и q
	p := generatePrimeNumber(bitLenght)
	q := generatePrimeNumber(bitLenght)

	// вычисляем их разность
	subPQ := new(big.Int).Sub(p, q)
	if subPQ.Sign() < 0 {
		subPQ.Mul(subPQ, iM1)
	}

	// если их разность маленькое число - повторяем процедуру генерации
	if len(subPQ.Bytes()) < minDiffLenght {
		goto Primes
	}

	// n = p * q
	n := new(big.Int).Mul(p, q)
	// φ(n) = (p - 1) * (q - 1)
	phiN := new(big.Int).Mul(new(big.Int).Sub(p, i1), new(big.Int).Sub(q, i1))

	// инициализируем буфер для генерации e
	// по станд
	kBytes := make([]byte, int(16))

Start:
	// заполняем буфер
	if _, err := io.ReadFull(rand.Reader, kBytes); err != nil {
		return nil, nil, err
	}

	// приведение к целочисленному значению
	e := new(big.Int).SetBytes(kBytes)

	// вычисляем значение по модулю φ(n)
	e = new(big.Int).Mod(e, phiN)

	// проверяем что e и φ(n) взаимнопростые
	// если нет, генерируем e еще раз
	if g, _, _ := extendedGCD(phiN, e); g.Cmp(i1) != 0 {
		goto Start
	}

	// вычисляем d, как ed = 1 mod φ(n)
	gcd, d, _ := extendedGCD(e, phiN)
	if gcd.Cmp(i1) != 0 {
		goto Start
	}

	// иницилизируем и возвращаем публичный и приватный ключи пользователя
	return NewPublicKey(e, n), NewPrivateKey(d), nil
}

// процедура шифрования
func (pubKey *PublicKey) ShipherBytes(M []byte) [][]byte {
	// инициализируем переменные для хранения шифра и m
	chipher := [][]byte{}
	m := [][]byte{}

	// дополняем сообщения до нужного размера блока
	PKCS7Padding(&M, blockSize)

	// разбиваем сообщения на блоки равной длины
	for i := 0; i < len(M); i += blockSize {
		m = append(m, M[i:i+blockSize])
	}

	// шифруем поблочно
	for _, mBytes := range m {
		// блок переводим в целое число
		mBlock := new(big.Int).SetBytes(mBytes)
		// вычисляем значени m * e (mod n) и записываем в массив
		chipher = append(chipher, exp(mBlock, pubKey.E, pubKey.N).Bytes())
	}

	// возврат массима блоков шифра
	return chipher
}

// процедура расшифрования
func (privKey *PrivateKey) DeShipherBytes(chiper [][]byte, pubKey *PublicKey) []byte {
	// инициализируем переменные для хранения М
	M := []byte{}

	// итерируемся по блокам шифра
	for _, mBytes := range chiper {
		// блок шифра переводим в целое число
		m := new(big.Int).SetBytes(mBytes)
		// вычисляем M = m * d (mod n)
		dechipher := exp(m, privKey.D, pubKey.N)
		// склеиваем блоки в исходное сообщение
		M = append(M, dechipher.Bytes()...)
	}

	// убираем дополнение блоков из расшифрованного текста
	PKCS7UnPadding(&M)

	// возврат расшифрованного сообщения
	return M
}
