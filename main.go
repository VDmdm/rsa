package main

import (
	"flag"
	"fmt"
	"math/big"
	"os"
	"rsa/utils"
	"strings"
	"time"
)

// Чтение публичного ключа из файла в параметре --public-key
func readPubkey(fKey string) (*utils.PublicKey, error) {
	// Читаем байтовое содержимое файла
	bytes, err := os.ReadFile(fKey)
	if err != nil {
		return nil, err
	}
	// Переводим в строку
	keyString := string(bytes)

	// Разбиваем на подстроки по переносу строки
	keyItems := strings.Split(keyString, "\n")
	// Проверяем что строк в файле было 2, если нет - вернуть ошибку
	if len(keyItems) != 2 {
		return nil, fmt.Errorf("Невозможно получить публичный ключ из файла. Неверное количество строк %d, должно быть 2", len(keyItems))
	}
	// Переводим строковое представление e в число
	e, ok := new(big.Int).SetString(keyItems[0], 10)
	// Если перевести в число не удалось - вернуть ошибку
	if !ok {
		return nil, fmt.Errorf("Невозможно получить e из файла. Она должен быть числом в десятичном представлении на первой строке.")
	}
	// Переводим строковое представление n в число
	n, ok := new(big.Int).SetString(keyItems[1], 10)
	// Если перевести в число не удалось - вернуть ошибку
	if !ok {
		return nil, fmt.Errorf("Невозможно получить n из файла. Она должен быть числом в десятичном представлении на второй строке.")
	}
	// инициализируем и возвращаем публичный ключ
	return utils.NewPublicKey(e, n), nil
}

// Чтение приватного ключа из файла в параметре --private-key
func readPrivkey(fKey string) (*utils.PrivateKey, error) {
	// Читаем байтовое содержимое файла
	bytes, err := os.ReadFile(fKey)
	if err != nil {
		return nil, err
	}
	// Переводим в строку
	keyString := string(bytes)
	// Разбиваем на подстроки по переносу строки
	keyItems := strings.Split(keyString, "\n")
	// Проверяем что в файле была 1 строка, если нет - вернуть ошибку
	if len(keyItems) != 1 {
		return nil, fmt.Errorf("Невозможно получить приватный ключ из файла. Неверное количество строк %d, должно быть 1", len(keyItems))
	}
	// Переводим строковое представление в число d
	d, ok := new(big.Int).SetString(keyItems[0], 10)
	// Если перевести в число не удалось - вернуть ошибку
	if !ok {
		return nil, fmt.Errorf("Невозможно приватный ключ из файла. Ключ должен быть числом в десятичном представлении.")
	}

	// Проверяем что d != 0
	if d.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("Невозможно получить приватный ключ, неверное содержимое файла")
	}
	return utils.NewPrivateKey(d), nil
}

// Генерация ключевой пары
func genKeyPair() (string, string, error) {
	// Генерируем публичный и приватный ключ, если произошла ошибка - возвращаем ее
	// Подробнее в utils/signature.go
	pubKey, privKey, err := utils.GenerateKeyPair()
	if err != nil {
		return "", "", err
	}

	// Получаем текущий штамп времени для формирования имени файла для записи ключей
	ts := time.Now().Format("20060102T150405")

	// Переводим X, Y точки проверки подписи (публичный ключ) в строковое предсталение с разбиение по переносу строки
	pubData := []byte(fmt.Sprintf("%s\n%s", pubKey.E, pubKey.N))
	// формируем имя файла
	pubKeyFile := fmt.Sprintf("%s_public.rsakey", ts)

	// Записываем строковое представление в файл
	err = os.WriteFile(pubKeyFile, pubData, 0600)
	if err != nil {
		return "", "", err
	}
	// Переводим D параметр подписи (приватный ключ) в строковое предсталение
	privData := []byte(privKey.D.String())

	// формируем имя файла
	privKeyFile := fmt.Sprintf("%s_private.rsakey", ts)

	// Записываем строковое представление в файл
	err = os.WriteFile(privKeyFile, privData, 0600)
	if err != nil {
		return "", "", err
	}

	// возвращаем имена файлов
	return pubKeyFile, privKeyFile, nil
}

func ChipherFile(filename, outputFile, publicKeyFile string) error {
	// Получаем публичный ключ из файла в параметре --public-key
	pKey, err := readPubkey(publicKeyFile)
	if err != nil {
		return err
	}

	// Читаем байтовое содержимое файла
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	// Формируем цифровую подпись
	// Подробнее в utils/signature.go
	chiper := pKey.ShipherBytes(bytes)
	if err != nil {
		return err
	}

	// Записываем шифр в файл переданный в параметре -o
	err = os.WriteFile(outputFile, []byte(chiper), 0600)
	return err
}

func DeChipherFile(filename, outputFile, publicKeyFile, privateKeyFile string) error {
	// Получаем публичный ключ из файла в параметре --public-key
	pubKey, err := readPubkey(publicKeyFile)
	if err != nil {
		return err
	}

	// Получаем приватный ключ из файла в параметре --private-key
	privKey, err := readPrivkey(privateKeyFile)
	if err != nil {
		return err
	}

	// Читаем байтовое содержимое файла
	chipher, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	// запускаем процедуру расшифрования
	// необходим и публичный ключ, потому что он содержит n
	M := privKey.DeShipherBytes(string(chipher), pubKey)

	// Записываем результат в файл, переданный в параметре -o
	err = os.WriteFile(outputFile, M, 0600)
	return err
}

func Wiener(filename, publicKeyFile, outputFile string) (bool, *big.Int, []*big.Rat, error) {
	// Получаем публичный ключ из файла в параметре --public-key
	pubKey, err := readPubkey(publicKeyFile)
	if err != nil {
		return false, nil, nil, err
	}

	// Читаем байтовое содержимое файла
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return false, nil, nil, err
	}

	// запускаем процедуру атаки
	// если завершится удачно, d != nil
	// также возвращает коэфициенты непрерывной дроби
	d, approx := utils.WienerAttack(pubKey.N, pubKey.E)

	if d != nil {
		// инициализируем приватный ключ полученным значением
		privateKey := utils.NewPrivateKey(d)

		// вызываем процедуру расшифрования
		M := privateKey.DeShipherBytes(string(bytes), pubKey)

		// Записываем результат в файл, переданный в параметре -o
		err = os.WriteFile(outputFile, M, 0600)
		return true, d, approx, err
	} else {
		return false, nil, approx, nil
	}
}

func main() {
	// установка перчня флагов (аргументов) принимаемых программой с их описанием
	fPath := flag.String("f", "", "Путь к файлу для защифрования или расшифрования")
	fPublicKey := flag.String("public-key", "", "Путь к файлу с публичным ключем пользователя")
	fPrivateKey := flag.String("private-key", "", "Путь к файлу с приватным ключем пользователя")
	outputFile := flag.String("o", "", "Путь к файлу куда сохранить результаты зашифрования или расшифрования")
	genMode := flag.Bool("gen", false, "Запуск в режиме генерации ключей пользователя.  Ключи сохраняются в текущий дериктории <timestamp>_public.rsakey и <timestamp>_private.rsakey")
	cMode := flag.Bool("enc", false, "Запуск в режиме зашифрования")
	dMode := flag.Bool("dec", false, "Запуск в режиме расшифрования")
	wMode := flag.Bool("wiener", false, "Запуск в режиме попытки проведения атаки Винера")

	// Парсим флаги
	flag.Parse()

	// проверяем что одновременно не заданы режим проверки и формирования подписи
	if (*cMode && *dMode) || (*cMode && *genMode) || (*genMode && *dMode) ||
		(*wMode && *dMode) || (*wMode && *genMode) || (*cMode && *wMode) {
		fmt.Println("Одновременно указаны несколько режимов работы. Это не допустимо, укажите один")
		os.Exit(1)
	}

	// режим генерации ключевой пары
	if *genMode {
		fmt.Println("Выбран режим генерации ключевой пары!")
		// запускаем процедуру генерации
		// в ней же происходит сохранение
		pubKey, privKey, err := genKeyPair()
		if err != nil {
			fmt.Printf("Во время генерации ключей произошла ошибка: %s\n", err.Error())
			os.Exit(1)
		}
		fmt.Println("Ключевая пара создана и сохранена успешно!")
		fmt.Printf("Публичный ключ: %s\n", pubKey)
		fmt.Printf("Приватный ключ: %s\n", privKey)
		os.Exit(0)
	}

	// Проверяем что задан путь к файлу
	if *fPath == "" {
		fmt.Println("Не указан путь к файлу. Укажите параметр --f <имя файла>")
		os.Exit(1)
	}

	// Проверяем что задан путь к файлу с ключом формирования подписи (приватный ключ)
	if *fPublicKey == "" {
		fmt.Println("Не указан путь к файлу с публичным ключом. Укажите параметр --public-key <имя файла>")
		os.Exit(1)
	}

	// Проверяем что задан путь к файлу с ключом формирования подписи (приватный ключ)
	if *outputFile == "" {
		fmt.Println("Не указан путь к файлу для сохранения результатов. Укажите параметр --o <имя файла>")
		os.Exit(1)
	}

	if *wMode {
		fmt.Println("Выбран режим попытки проведения атаки Винера!")
		fmt.Printf("Путь к файлу: %s\n", *fPath)
		fmt.Printf("Путь к файлу публичного ключа: %s\n", *fPublicKey)

		ok, d, approx, err := Wiener(*fPath, *fPublicKey, *outputFile)
		if err != nil {
			fmt.Printf("Во время попытки атаки Винера произошла ошибка: %s\n", err.Error())
			os.Exit(1)
		}

		if ok {
			fmt.Printf("Атака завершилась успешно. Публичный ключ d = %s\n", d)
			fmt.Printf("Были подобраны следующие коэфициенты непрерывной дроби: [")
			for i := 0; i < len(approx); i++ {
				d := approx[i].Num()
				fmt.Printf("%s ", d)
			}
			fmt.Println("]")
			fmt.Printf("Файл успешно расшифрован. Результат в файле: %s\n", *outputFile)
		} else {
			fmt.Println("Атака завершилась неудачно. Приватный ключ не найден.")
			fmt.Printf("Были подобраны следующие коэфициенты непрерывной дроби: [")
			for i := 0; i < len(approx); i++ {
				d := approx[i].Num()
				fmt.Printf("%s ", d)
			}
			fmt.Println("]")
		}
		os.Exit(0)
	}

	// Проверяем что задан путь к файлу с ключом формирования подписи (приватный ключ)
	if *fPrivateKey == "" {
		fmt.Println("Не указан путь к файлу с приватным ключом. Укажите параметр --private-key <имя файла>")
		os.Exit(1)
	}

	// режим зашифрования
	if *cMode {
		fmt.Println("Выбран режим зашифрования")
		fmt.Printf("Путь к файлу: %s\n", *fPath)
		fmt.Printf("Путь к файлу приватного ключа: %s\n", *fPrivateKey)
		fmt.Printf("Путь к файлу публичного ключа: %s\n", *fPublicKey)

		// запускаем процедуру зашифрования
		// в ней же происходит сохранение файлов
		err := ChipherFile(*fPath, *outputFile, *fPublicKey)
		if err != nil {
			fmt.Printf("Во время зашифрования произошла ошибка: %s\n", err.Error())
			os.Exit(1)
		}
		fmt.Printf("Файл успешно зашифрован. Результат в файле: %s\n", *outputFile)
		os.Exit(0)
	}

	// процедура расшифрования
	if *dMode {
		fmt.Println("Выбран режим расшифрования")
		fmt.Printf("Путь к файлу: %s\n", *fPath)
		fmt.Printf("Путь к файлу приватного ключа: %s\n", *fPrivateKey)
		fmt.Printf("Путь к файлу публичного ключа: %s\n", *fPublicKey)

		// запускаем процедуру расшифрования
		// в ней же происходит сохранение файлов
		err := DeChipherFile(*fPath, *outputFile, *fPublicKey, *fPrivateKey)
		if err != nil {
			fmt.Printf("Во время расшифрования произошла ошибка: %s\n", err.Error())
			os.Exit(1)
		}
		fmt.Printf("Файл успешно расшифрован. Результат в файле: %s\n", *outputFile)
		os.Exit(0)
	}
	fmt.Println("Не указан режим работы программы. Исползуйте -h для вызова справки")
}

// https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/amp/
