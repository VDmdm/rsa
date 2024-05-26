package utils

import "math/big"

// Функция для нахождения рациональных приближений (непрерывная дробь)
func rationalApproximations(numerator, denominator *big.Int) []*big.Rat {
	// инициализируем массив и пеерменные
	approx := []*big.Rat{}
	a, b := new(big.Int).Set(numerator), new(big.Int).Set(denominator)

	// пока b != 0
	for b.Cmp(big.NewInt(0)) != 0 {
		// вычисляем целую часть от деления
		quotient := new(big.Int).Div(a, b)
		// добавляем в массив
		approx = append(approx, new(big.Rat).SetInt(quotient))
		// a = b, b = a mod b
		a, b = b, new(big.Int).Mod(a, b)
	}

	// возвращаем список
	return approx
}

// Проверка, является ли найденное значение правильным приватным ключом
func isPotentialKey(e, k, d, n *big.Int) bool {
	ed := new(big.Int).Mul(e, d)
	phi := new(big.Int).Sub(ed, big.NewInt(1))
	return new(big.Int).Mod(phi, k).Cmp(big.NewInt(0)) == 0
}

// Основная функция для атаки Винера
func WienerAttack(n, e *big.Int) (*big.Int, []*big.Rat) {
	// получаем рациональные приближения (раскладываем непрерывную дробь)
	approx := rationalApproximations(e, n)
	for i := 0; i < len(approx); i++ {
		// получаем значения k и d
		k := approx[i].Denom()
		d := approx[i].Num()

		// проверяем что d может быть потенциальным ключом
		if k.Cmp(big.NewInt(0)) != 0 && d.Cmp(big.NewInt(0)) != 0 && isPotentialKey(e, k, d, n) {
			// Проверяем, что d действительно является приватным ключом
			// зашифровываем цифру 2
			test := new(big.Int).Exp(big.NewInt(2), d, n)
			// расшифровываем
			encrypted := new(big.Int).Exp(test, e, n)

			// проверяем что результат расшифрования == 2
			if encrypted.Cmp(big.NewInt(2)) == 0 {
				return d, approx
			}
		}
	}
	return nil, approx
}
