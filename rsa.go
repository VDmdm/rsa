package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"rsa/utils"
	"strings"
	"time"
)

// Чтение публичного ключа из файла в параметре --key
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
	// Переводим строковое представление координаты X в число
	e, ok := new(big.Int).SetString(keyItems[0], 10)
	// Если перевести в число не удалось - вернуть ошибку
	if !ok {
		return nil, fmt.Errorf("Невозможно получить координату Х из файла. Она должен быть числом в десятичном представлении на первой строке.")
	}
	// Переводим строковое представление координаты Y в число
	n, ok := new(big.Int).SetString(keyItems[1], 10)
	// Если перевести в число не удалось - вернуть ошибку
	if !ok {
		return nil, fmt.Errorf("Невозможно получить координату Y из файла. Она должен быть числом в десятичном представлении на второй строке.")
	}
	// инициализируем и возвращаем публичный ключ
	return utils.NewPublicKey(e, n), nil
}

// Чтение приватного ключа из файла в параметре --key
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
		return nil, fmt.Errorf("Невозможно получить публичный ключ из файла. Неверное количество строк %d, должно быть 1", len(keyItems))
	}
	// Переводим строковое представление в число d
	d, ok := new(big.Int).SetString(keyItems[0], 10)
	// Если перевести в число не удалось - вернуть ошибку
	if !ok {
		return nil, fmt.Errorf("Невозможно ключ из файла. Ключ должен быть числом в десятичном представлении.")
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
	// Получаем приватный ключ из файла в параметре --key
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

	chipherHexString := ""

	for _, ch := range chiper {
		hexString := hex.EncodeToString(ch)
		chipherHexString += hexString + "\n"
	}

	// Записываем число в файл переданный в параметре --signature
	err = os.WriteFile(outputFile, []byte(chipherHexString), 0600)
	return err
}

func DeChipherFile(filename, outputFile, publicKeyFile, privateKeyFile string) error {
	// Получаем приватный ключ из файла в параметре --key
	pubKey, err := readPubkey(publicKeyFile)
	if err != nil {
		return err
	}

	privKey, err := readPrivkey(privateKeyFile)
	if err != nil {
		return err
	}

	// Читаем байтовое содержимое файла
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	chipher := [][]byte{}

	fileLine := strings.Split(string(bytes), "\n")

	for _, l := range fileLine {
		if l == "" {
			continue
		}
		chBytes, err := hex.DecodeString(l)
		if err != nil {
			return err
		}

		chipher = append(chipher, chBytes)
	}

	M := privKey.DeShipherBytes(chipher, pubKey)

	// Записываем число в файл переданный в параметре --signature
	err = os.WriteFile(outputFile, M, 0600)
	return err
}

func main() {
	// установка перчня флагов (аргументов) принимаемых программой с их описанием
	fPath := flag.String("f", "", "Путь к файлу для защифрования или расшифрования")
	fPublicKey := flag.String("public-key", "", "Путь к файлу с публичным ключем пользвоателя")
	fPrivateKey := flag.String("private-key", "", "Путь к файлу с приватным ключем пользвоателя")
	genMode := flag.Bool("gen", false, "Запуск в режиме генерации ключей пользователя.  Ключи сохраняются в текущий дериктории <timestamp>_public.rsakey и <timestamp>_private.rsakey")
	sMode := flag.Bool("enc", false, "Запуск в режиме подписи файла")
	vMode := flag.Bool("dec", false, "Запуск в режиме проверки подписи файла")

	// Парсим флаги
	flag.Parse()

	// проверяем что одновременно не заданы режим проверки и формирования подписи
	if *sMode && *vMode {
		fmt.Println("Одновременно указаны режим подписи и проверки подписи. Это не допустимо, укажите один")
		os.Exit(1)
	}

	pubKey, privKey, err := utils.GenerateKeyPair()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	M := []byte("AbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAbobaAboba1")
	chipher := pubKey.ShipherBytes(M)
	dechipher := privKey.DeShipherBytes(chipher, pubKey)

	fmt.Println(string(dechipher))

}

// https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/amp/
