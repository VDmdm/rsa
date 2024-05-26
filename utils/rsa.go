package utils

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

var (
	// битовая длина для генерации p / q
	bitLenght = 7
	// // размер блока шифр текста в байтах
	// blockSize = (bitLenght - 1)
	// минимальная битовая длина |p - q|
	minDiffLenght = bitLenght/4 + 1
)

// Тип для представления публичного ключа
type PublicKey struct {
	E *big.Int
	N *big.Int
}

// Тип для представления приватного ключа
type PrivateKey struct {
	D *big.Int
}

// "Конструктор" для инициализации публичного ключа
func NewPublicKey(e, n *big.Int) *PublicKey {
	return &PublicKey{
		E: e,
		N: n,
	}
}

// "Конструктор" для инициализации приватного ключа
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
	if subPQ.BitLen() < minDiffLenght {
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
func (pubKey *PublicKey) ShipherBytes(M []byte) string {
	// инициализируем переменные для хранения шифра и m
	var bitsM string
	var chipher string
	m := []string{}

	// m := [][]byte{}

	// получаем log2(n) с округлением в меньшую сторону
	// размер блока
	logN := log2(pubKey.N)

	for _, bytes := range M {
		bitsM += fmt.Sprintf("%08b", bytes)
	}

	// разбиваем на блоки log2(n) битовое представление сообщения
	var i int64
	for i = int64(len(bitsM)); i > int64(0); i -= logN {
		// инициализируем переменную для хранения блока
		var blockM string
		// проверяем что блок не последний
		if i-logN < 0 {
			blockM = bitsM[:i]
		} else {
			// если последний - отрезаем до конца
			blockM = bitsM[i-logN : i]
		}
		// добавляем блок в массив блоков
		m = append(m, blockM)
	}

	// вычисляем длину последнего блока сообщения
	l := int64(len(m[len(m)-1]))

	// если последний блок меньше чем нужно
	// дополняем его нолями слева
	if l != logN {
		var blockM string
		for i := l; i < logN; i++ {
			blockM += "0"
		}
		m[len(m)-1] = blockM + m[len(m)-1]
	}

	// шифруем поблочно
	for _, mBytes := range m {
		// блок переводим в целое число
		mBlock, _ := new(big.Int).SetString(mBytes, 2)

		chiperbits := exp(mBlock, pubKey.E, pubKey.N).Text(2)

		if int64(len(chiperbits)) < int64(logN+1) {
			for i := len(chiperbits); i < int(logN)+1; i++ {
				chiperbits = "0" + chiperbits
			}
		}

		// вычисляем значени m * e (mod n) и записываем в массив
		chipher += chiperbits
	}

	// возврат массима блоков шифра
	return chipher
}

// процедура расшифрования
func (privKey *PrivateKey) DeShipherBytes(chiper string, pubKey *PublicKey) []byte {
	// инициализируем переменные для хранения М
	bitM := []string{}
	M := []byte{}
	chipherBlocks := []string{}

	// получаем log2(n) с округлением в меньшую сторону
	// размер блока
	logN := log2(pubKey.N)

	// вставить проверку chipher % log2(n) + 1

	for i := int64(0); i < int64(len(chiper)); i += logN + 1 {
		chipherBlocks = append(chipherBlocks, chiper[i:i+logN+1])
	}

	// итерируемся по блокам шифра
	for _, cBites := range chipherBlocks {
		// блок шифра переводим в целое число
		c, _ := new(big.Int).SetString(cBites, 2)
		// вычисляем M = m * d (mod n)
		dechipher := exp(c, privKey.D, pubKey.N)
		// переводим в битовое представление
		bitM = append(bitM, fmt.Sprintf("%08b", dechipher))
	}

	// итерируемся по битовому представлению M и дополняем до исходного размера блоков
	for i := range bitM {
		// вычисляем длину блока
		l := int64(len(bitM[i]))

		// инициализируем переменную для записи недостающих бит
		var blockM string
		// если длина блока меньше, заполняем по недостающему количеству нулями
		for i := l; i < logN; i++ {
			blockM += "0"
		}

		// склеиваем нули и блок
		bitM[i] = blockM + bitM[i]
	}

	// переменная для кокнатенации блоков в одну битовую строку
	var m string
	for i := len(bitM) - 1; i >= 0; i-- {
		m += bitM[i]
	}

	// бьем на блоки по 8 бит с конца, приводим к сообщение к исходному виду
	for i := len(m); i >= 0; i -= 8 {
		if i-8 < 0 {
			break
		}
		c, _ := new(big.Int).SetString(m[i-8:i], 2)
		M = append(c.Bytes(), M...)
	}

	// возвращаем расшифрованное сообщение
	return M
}
