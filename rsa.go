package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
)

var (
	iM1        = big.NewInt(-1)
	i0         = big.NewInt(0)
	i1         = big.NewInt(1)
	i2         = big.NewInt(2)
	byteLenght = 512 // 4096 бит
	blockSize  = byteLenght / 8
)

type PublicKey struct {
	e *big.Int
	n *big.Int
}

type Privatekey struct {
	d *big.Int
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

func GenerateKeyPair() (*PublicKey, *Privatekey, error) {
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

	pubKey := &PublicKey{
		e: e,
		n: n,
	}

	privKey := &Privatekey{
		d: d,
	}

	return pubKey, privKey, nil
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
		chipher = append(chipher, exp(mBlock, pubKey.e, pubKey.n).Bytes())
	}

	return chipher
}

func (privKey *Privatekey) DeShipherBytes(chiper [][]byte, n *big.Int) []byte {
	M := []byte{}
	for _, mBytes := range chiper {
		m := new(big.Int).SetBytes(mBytes)
		dechipher := exp(m, privKey.d, n)
		M = append(M, dechipher.Bytes()...)
	}

	PKCS7UnPadding(&M)

	return M
}

func main() {
	// установка перчня флагов (аргументов) принимаемых программой с их описанием
	fPath := flag.String("f", "", "Путь к файлу для подписания или проверки подписи")
	fSignature := flag.String("signature", "", "Пусть к файлу с подписью. Для режима проверки будет считан, для режима подписания будет создан")
	fPublicKey := flag.String("publickey", "", "Файл с ключом подписи (приватный ключ) для режима подписи или с ключом проверки подписи (публичный ключ) для режима проверки подписи")
	fPrivateKey := flag.String("publickey", "", "Файл с ключом подписи (приватный ключ) для режима подписи или с ключом проверки подписи (публичный ключ) для режима проверки подписи")
	genMode := flag.Bool("gen", false, "Запуск в режиме генерации ключей пользователя.  Ключи сохраняются в текущий дериктории <timestamp>_public.sigkey и <timestamp>_private.sigkey")
	sMode := flag.Bool("sign-file", false, "Запуск в режиме подписи файла")
	vMode := flag.Bool("verify-sign", false, "Запуск в режиме проверки подписи файла")
	param := flag.String("params", "id-tc26-gost-3410-12-512-paramSetA", "Выбор параметров элептической кривой. По умолчанию: id-tc26-gost-3410-12-512-paramSetB. Может быть один из [id-GostR3410-2001-CryptoPro-A-ParamSet, id-GostR3410-2001-CryptoPro-B-ParamSet, id-GostR3410-2001-CryptoPro-C-ParamSet, id-tc26-gost-3410-12-512-paramSetA, id-tc26-gost-3410-12-512-paramSetB]")

	// Парсим флаги
	flag.Parse()

	pubKey, privKey, err := GenerateKeyPair()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	M := []byte("AbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAboba1")
	chipher := pubKey.ShipherBytes(M)
	dechipher := privKey.DeShipherBytes(chipher, pubKey.n)

	fmt.Println(string(dechipher))

}

// https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/amp/
