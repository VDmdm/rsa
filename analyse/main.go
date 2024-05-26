package main

import (
	"fmt"
	"math/big"
)

// Функция для нахождения рациональных приближений (continued fractions)
func rationalApproximations(numerator, denominator *big.Int) []*big.Rat {
	approx := []*big.Rat{}
	a, b := new(big.Int).Set(numerator), new(big.Int).Set(denominator)

	for b.Cmp(big.NewInt(0)) != 0 {
		quotient := new(big.Int).Div(a, b)
		approx = append(approx, new(big.Rat).SetInt(quotient))
		a, b = b, new(big.Int).Mod(a, b)
	}

	return approx
}

// Проверка, является ли найденное значение правильным приватным ключом
func isPotentialKey(e, k, d, n *big.Int) bool {
	ed := new(big.Int).Mul(e, d)
	phi := new(big.Int).Sub(ed, big.NewInt(1))
	return new(big.Int).Mod(phi, k).Cmp(big.NewInt(0)) == 0
}

// Основная функция для атаки Винера
func wienerAttack(n, e *big.Int) *big.Int {
	approx := rationalApproximations(e, n)
	for i := 0; i < len(approx); i++ {
		k := approx[i].Denom()
		d := approx[i].Num()

		if k.Cmp(big.NewInt(0)) != 0 && d.Cmp(big.NewInt(0)) != 0 && isPotentialKey(e, k, d, n) {
			// Проверяем, что d действительно является приватным ключом
			test := new(big.Int).Exp(big.NewInt(2), d, n)
			encrypted := new(big.Int).Exp(test, e, n)
			if encrypted.Cmp(big.NewInt(2)) == 0 {
				return d
			}
		}
	}
	return nil
}

func main() {
	// Пример значений публичного ключа
	n := new(big.Int)
	e := new(big.Int)
	ciphertext := new(big.Int)

	// Введите значения n, e и зашифрованного текста
	n.SetString("713", 10)
	e.SetString("11", 10)
	ciphertext.SetString("000101001101110001011101000011111000110", 2)

	// Выполняем атаку Винера
	d := wienerAttack(n, e)
	if d != nil {
		fmt.Printf("Найден приватный ключ d: %s\n", d.String())

		// Расшифровываем сообщение
		plaintext := new(big.Int).Exp(ciphertext, d, n)

		fmt.Printf("Расшифрованное сообщение: %s\n", string(plaintext.Bytes()))
	} else {
		fmt.Println("Не удалось найти приватный ключ с использованием атаки Винера.")
	}
}
