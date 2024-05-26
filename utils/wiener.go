package utils

import (
	"math/big"
)

// Функция для превращения в непрерывную дробь
func rationalApproximations(numerator, denominator *big.Int) []*big.Int {
	// инициализируем массив и пеерменные
	approx := []*big.Int{}
	a, b := new(big.Int).Set(numerator), new(big.Int).Set(denominator)

	// пока b != 0
	for b.Cmp(big.NewInt(0)) != 0 {
		// вычисляем целую часть от деления
		quotient := new(big.Int).Div(a, b)
		// добавляем в массив
		approx = append(approx, quotient)
		// a = b, b = a mod b
		a, b = b, new(big.Int).Mod(a, b)
	}

	// возвращаем список
	return approx
}

// функция нахождения рациональных приближений
func convergents(quotients []*big.Int) [][2]*big.Int {
	// инициализуем переменную для хранения дроби
	convergents := make([][2]*big.Int, len(quotients))
	// итерируемся по коэфициентам непрерывной дроби
	for i := 0; i < len(quotients); i++ {
		// временный переменные для записи числителя и знаменателя
		var num, den *big.Int
		// если это первый коэффициент
		if i == 0 {
			// устанавливаем 0/1, по сути это 0
			num = new(big.Int).Set(quotients[i])
			den = big.NewInt(1)
		} else if i == 1 {
			// первый коэфициент высчитывается иначе чем остальные, потому что перед ним идет 0
			// просто добавляем к нему единицу потому что там 0
			num = new(big.Int).Mul(quotients[i], quotients[i-1])
			num.Add(num, i1)
			den = new(big.Int).Set(quotients[i])
		} else {
			// для всех остальных случаев
			// числитель - умножаем текущий коэфициент на предыдущий числитель
			num = new(big.Int).Mul(quotients[i], convergents[i-1][0])
			// добавляем к нему числитель позапрошлого элемента
			num.Add(num, convergents[i-2][0])
			// знаменатель - умножаем ткущий коэффициент на прошый знаменатель
			den = new(big.Int).Mul(quotients[i], convergents[i-1][1])
			// добавляем к нему знаменатель позапрошлого элемента
			den.Add(den, convergents[i-2][1])
		}
		// записываем результат
		convergents[i][0] = num
		convergents[i][1] = den
	}
	return convergents
}

// Проверка, является ли найденное значение правильным приватным ключом
func isPotentialKey(e, k, d, n *big.Int) bool {
	ed := new(big.Int).Mul(e, d)
	phi := new(big.Int).Sub(ed, big.NewInt(1))
	return new(big.Int).Mod(phi, k).Cmp(big.NewInt(0)) == 0
}

// Основная функция для атаки Винера
func WienerAttack(n, e *big.Int) (*big.Int, [][2]*big.Int) {
	// получаем рациональные приближения (раскладываем непрерывную дробь)
	approx := rationalApproximations(e, n)
	quotients := convergents(approx)

	for i := 0; i < len(quotients); i++ {
		// получаем значения k и d
		// дробь Pi/Qi, где Qi кандидат в d
		k := quotients[i][0]
		d := quotients[i][1]

		// проверяем что d может быть потенциальным ключом
		if k.Cmp(big.NewInt(0)) != 0 && d.Cmp(big.NewInt(0)) != 0 && isPotentialKey(e, k, d, n) {
			// Проверяем, что d действительно является приватным ключом
			// зашифровываем цифру 2
			test := new(big.Int).Exp(big.NewInt(2), d, n)
			// расшифровываем
			encrypted := new(big.Int).Exp(test, e, n)

			// проверяем что результат расшифрования == 2
			if encrypted.Cmp(big.NewInt(2)) == 0 {
				return d, quotients
			}
		}
	}

	return nil, quotients
}
