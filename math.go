package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

func exp(integer, pow, modulus *big.Int) *big.Int {
	integerBinary := strings.Split(fmt.Sprintf("%b", pow), "")

	A := big.NewInt(0).Add(integer, big.NewInt(0))
	b := big.NewInt(1)
	if integerBinary[0] == "0" || modulus.Cmp(big.NewInt(1)) == 0 {
		return b
	}

	if integerBinary[len(integerBinary)-1] == "1" {
		b = new(big.Int).Add(A, big.NewInt(0)) // копирую
	}

	for idx := len(integerBinary) - 2; idx >= 0; idx-- {
		A = new(big.Int).Exp(A, big.NewInt(2), modulus)
		if integerBinary[idx] == "1" {
			b = new(big.Int).Mul(A, b)
			b = new(big.Int).Mod(b, modulus)
		}
	}
	return b
}

func testForPrime(n *big.Int, count int) bool {
	history := make(map[string]bool, count)

	pow := new(big.Int).Sub(n, i1)
	candidate := new(big.Int)
	for i := 0; i < count; i++ {
		candidate, _ = rand.Int(rand.Reader, new(big.Int).Sub(n, i2))
		candidate = new(big.Int).Add(candidate, i2)
		if _, ok := history[candidate.String()]; ok && new(big.Int).Mod(candidate, i2).Cmp(i1) != 0 {
			i--
		} else {
			c := exp(candidate, pow, n)
			if c.Cmp(i1) != 0 {
				return false
			}
		}
	}
	return true
}

func generatePrimeNumber(bits int) *big.Int {
	for {
		prime := new(big.Int).SetBit(i0, bits, 0x01)
		rand, _ := rand.Int(rand.Reader, prime)

		prime = new(big.Int).Xor(prime, rand)
		if new(big.Int).Mod(prime, i2).Cmp(i1) != 0 {
			continue
		} else {
			if passed := testForPrime(prime, 1024); passed {
				return prime
			}
		}
	}
}

// Расширенный алгоритм Евклида
func extendedGCD(a_src, b_src *big.Int) (*big.Int, *big.Int, *big.Int) {
	// Клонируем входные точки, чтобы они не изменились в процессе вычислений
	a, b := new(big.Int).Set(a_src), new(big.Int).Set(b_src)
	// Инициализируем переменные
	q, r, x, y := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	x2, x1 := big.NewInt(1), big.NewInt(0)
	y2, y1 := big.NewInt(0), big.NewInt(1)

	// Пока и b != 0
	for b.Cmp(i0) != 0 {
		// q = a / b
		q = new(big.Int).Div(a, b)
		// r = a mod b
		r = new(big.Int).Mod(a, b)
		// x = x2 - qx1
		qx := new(big.Int).Mul(q, x1)
		x = new(big.Int).Sub(x2, qx)
		// y = y2 - qy1
		qy := new(big.Int).Mul(q, y1)
		y = new(big.Int).Sub(y2, qy)
		// x2 <- x1
		x2 = new(big.Int).Set(x1)
		// y2 <- y1
		y2 = new(big.Int).Set(y1)
		// x1 <- x
		x1 = new(big.Int).Set(x)
		// y1 <- y
		y1 = new(big.Int).Set(y)
		// a <- b
		a = new(big.Int).Set(b)
		// b <- r
		b = new(big.Int).Set(r)
	}
	return a, x2, y2
}
