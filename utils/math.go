package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

var (
	iM1 = big.NewInt(-1)
	i0  = big.NewInt(0)
	i1  = big.NewInt(1)
	i2  = big.NewInt(2)
)

// умножение больших числе по модулю
func exp(integer, pow, modulus *big.Int) *big.Int {
	// получаем битовое представление степени
	integerBinary := strings.Split(fmt.Sprintf("%b", pow), "")

	// ининиализируем a, b
	A := new(big.Int).Set(integer)
	b := new(big.Int).Set(i1)

	// если старший бит равен 0 или модуль равен 1 - возврат b (1)
	if integerBinary[0] == "0" || modulus.Cmp(big.NewInt(1)) == 0 {
		return b
	}

	// если старший бит равен 1
	// копируем в b значение а
	if integerBinary[len(integerBinary)-1] == "1" {
		b = new(big.Int).Add(A, big.NewInt(0)) // копирую
	}

	// итерируемся по битовой строке modulus
	for idx := len(integerBinary) - 2; idx >= 0; idx-- {
		// a = a * 2 (mod n)
		A = new(big.Int).Mul(A, A)
		A.Mod(A, modulus)
		// если текущий бит == 1
		if integerBinary[idx] == "1" {
			// b = a * b (mod n)
			b = new(big.Int).Mul(A, b)
			b = new(big.Int).Mod(b, modulus)
		}
	}

	// возврат b
	return b
}

// тест на простоту
// принимает число для тестирования и количество тестов
func testForPrime(n *big.Int, count int) bool {
	// создаем хранилище для записи уже сгенерированных значений
	// чтобы исключить повторение при рандомном выборе числа
	history := make(map[string]bool, count)

	// вычисляем степень
	// pow = n - 1
	pow := new(big.Int).Sub(n, i1)

	// инициализируем переменную, в которой будем хранить кандидата (сгенерированное число из от 2 до n-1)
	candidate := new(big.Int)

	// повторяем количество раз из count
	for i := 0; i < count; i++ {
		// генерируем случайное число-кандидат от 0 до n-3 (включительно)
		// от 0, потому что программная реализация не позволяет указать нижнюю границу
		candidate, _ = rand.Int(rand.Reader, new(big.Int).Sub(n, i2))
		// добавляем к получившему-ся числу 2, такие образом из от 0 до n-3
		// получаем от 2 до n-1
		candidate = new(big.Int).Add(candidate, i2)
		// если сгенерированный кандидат уже был проверен пропускаем
		if _, ok := history[candidate.String()]; ok && new(big.Int).Mod(candidate, i2).Cmp(i1) != 0 {
			i--
		} else {
			// возводим кандидата в степень n -1 по модулю n
			c := exp(candidate, pow, n)
			// если резульат != 1, возвращаем false, тест провален
			if c.Cmp(i1) != 0 {
				return false
			}
			// сохраняем информацию о протестированном кандидате
			history[candidate.String()] = true
		}
	}

	// если прошел нужное количество проверок - возвращаем true, тест пройден
	return true
}

func generatePrimeNumber(bits int) *big.Int {
	for {
		// создаем новое число, устанавливаем в нужный бит единицу
		// гарантирует что число будет не меньше нужно битовой длины
		prime := new(big.Int).SetBit(i0, bits, 0x01)

		// генерируем число в диапазоне от 0 до прошлое число - 1
		// так как прошлое число это 10000...000 (по количеству бит)
		// -1 от него гарантировано даст битовую длину меньше на единицу от заданой
		rand, _ := rand.Int(rand.Reader, prime)

		// ксорим первое число (где был установлен 1 бит) со сгенерированным значением и получаем кандидата
		prime = new(big.Int).Xor(prime, rand)

		// если кандидат четный, перезапускаем процедуру генерации
		if new(big.Int).Mod(prime, i2).Cmp(i1) != 0 {
			continue
		} else {
			// проводим тест на простоту 1024 раза
			// если пройден - возвращаем число
			// если нет - процедура перезапускается заного
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
