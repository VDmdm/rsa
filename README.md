## RSA

## Запуск программы
```sh
git clone git@github.com:VDmdm/rsa.git
cd rsa/
go mod download
go run main.go [flags]
```
или
```sh
git clone git@github.com:VDmdm/rsa.git
cd rsa/
go mod download
go build main.go -o rsa
./rsa [flags]
```
## Флаги запуска [flags]
- -f [строка: путь к файлу] – путь к файлу для защифрования или расшифрования;
- -public-key [строка: путь к файлу] – путь к файлу с публичным ключем пользователя;
- -private-key [строка: путь к файлу] – путь к файлу с приватным ключем пользователя;
- -o [строка: путь к файлу] – путь к файлу куда сохранить результаты зашифрования или расшифрования;
- -gen - Запуск в режиме генерации ключей пользователя.  Ключи сохраняются в текущий дериктории <timestamp>_public.rsakey и <timestamp>_private.rsakey;
- -enc - Запуск в режиме зашифрования;
- -dec - Запуск в режиме расшифрования.

## Пример работы программы
```sh
// генерация ключей
go run main.go --gen
//Выбран режим генерации ключевой пары!
//Ключевая пара создана и сохранена успешно!
//Публичный ключ: 20240520T002450_public.rsakey
//Приватный ключ: 20240520T002450_private.rsakey

// шифрование файла
go run main.go -enc -f text.txt -private-key 20240520T002450_private.rsakey -public-key 20240520T002450_public.rsakey -o text_enc.txt
//Выбран режим зашифрования
//Путь к файлу: text.txt
//Путь к файлу приватного ключа: 20240520T002450_private.rsakey
//Путь к файлу публичного ключа: 20240520T002450_public.rsakey
//Файл успешно зашифрован. Результат в файле: text_enc.txt

//расшифрование файла
go run main.go -dec -f text_enc.txt -private-key 20240520T002450_private.rsakey -public-key 20240520T002450_public.rsakey -o text_dec.txt
//Выбран режим проверки подписи файла.
//Путь к файлу: example/file.txt
//Путь к файлу подписи: example/sign.txt
//Путь к файлу приватного ключа: 20240520T002450_private.rsakey
//Путь к файлу публичного ключа: 20240520T002450_public.rsakey
//Проверка подписи завершена.
//Подпись верна.

```