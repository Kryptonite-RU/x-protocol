### English

X-protocol python 3 realization.

# 0. Prerequisites for launching / testing

Modules: pygost, datetime, json
Python: version >= 3.5

# 1. Running tests

It is necessary to execute the following operation in the command line:

`python -m unittest discover`

# 2. Сommand line utilities

You can use an additional key in all the commands below.
`--verbose` to display additional information.
All default paths are in the default.py file.

## 2.1 Service commands

### 2.1.1 Request generation

For this operation, you must run the following on the command line:

`python -m cmd.src --form --uid <user-id:int> --scope <data-scope:str> --due <date>`

There are also optional arguments:

1. `--output <path-to-file>` -- file path (including file name), where the generated
   request will be saved, the default path = `data/request`.
2. `--service <path-to-service>` -- path to the file with keys and additional information
   about the service, the default path is = `data/src`, it can be changed in default.py file or passed
   directly to the command line.
3. `--auth <path-to-auth>` -- path to the file with a certificate authority database
   (provides the scope -> inspector map etc.)

For example:

`python -m cmd.src --form --uid 123 --scope "passport" --due 2099-01-01`

**The date is written as YYYY-MM-DD.**

### 2.1.2 Blob signature validation (coming from user)

For this operation, you must run the following on the command line:

`python -m cmd.src --check --blob <path-to-blob>`

There are also optional arguments:

1. `--service <path-to-service>` -- path to the file with keys and additional information
   about the service, the default path is = `data/src`, it can be changed in default.py file or passed
   directly to the command line.
2. `--auth <path-to-auth>` -- path to the file with a certificate authority database
   (provides the scope -> inspector map etc.)


### 2.1.3 Inspector response validation

For this operation, you must run the following on the command line:

`python -m cmd.src --check --response <path-to-response>`

There are also optional arguments:

1. `--service <path-to-service>` -- path to the file with keys and additional information
   about the service, the default path is = `data/src`, it can be changed in default.py file or passed
   directly to the command line.
2. `--auth <path-to-auth>` -- path to the file with a certificate authority database
   (provides the scope -> inspector map etc.)

Using this operation, the service verifies the signature of the inspector,
as well as the response confirmation (whether the encrypted personal data
provided in the blob is correct).

## 2.2 User commands

### 2.2.1 Blob generation

For this operation, you must run the following on the command line:

`python -m cmd.usr --form --request <path-to-request>`

There are also optional arguments:

1. `--output <path-to-file>` -- file path (including file name), where the generated
   blob will be saved, the default path = `data/blob`.
2. `--secdata <personal data>` -- user personal data, which corresponds the request.
   If the personal data is not provided during the command execution, then it will be
   requested (together with the output information about the service ID, scope and data,
   until which the personal data is required).
2. `--user <path-to-user>` -- path to the file with keys and additional information
   about the user, the default path is = `data/usr`, it can be changed in default.py file or passed
   directly to the command line.
3. `--auth <path-to-auth>` -- path to the file with a certificate authority database
   (provides the scope -> inspector map etc.).

For example:

`python -m cmd.usr --form --request data/request --secdata "Ivanov Ivan Ivanovich"` 

### 2.2.2 Request validation (signature)

For this operation, you must run the following on the command line:

`python -m cmd.usr --check --request <path-to-request>`

There are also optional arguments:

1. `--user <path-to-user>` -- path to the file with keys and additional information
   about the user, the default path is = `data/usr`, it can be changed in default.py file or passed
   directly to the command line.
2. `--auth <path-to-auth>` -- path to the file with a certificate authority database
   (provides the scope -> inspector map etc.).

## 2.3 Inspector commands

### 2.3.1 Blob verification

For this operation, you must run the following on the command line:

`python -m cmd.insp --verify --blob <path-to-blob>`

There are also optional arguments:

1. `--output <path-to-file>` -- file path (including file name), where the generated
   response will be saved, the default path = `data/response`.
2. `--inspector <path-to-inspector>` -- path to the file with keys and additional information
   about the user, the default path is = `data/insp`, it can be changed in default.py file or passed
   directly to the command line.
3. `--auth <path-to-auth>` -- path to the file with a certificate authority database
   (provides the scope -> inspector map etc.).

For example:

`python -m cmd.insp --verify --blob data/blob` 

### 2.3.2 User personal data addition 

For this operation, you must run the following on the command line:

`python -m cmd.insp --add --uid <user-id:int> --secdata <data : str>`

There are also optional arguments:

1. `--inspector <path-to-inspector>` -- path to the file with keys and additional information
   about the user, the default path is = `data/insp`, it can be changed in default.py file or passed
   directly to the command line.
2. `--auth <path-to-auth>` -- path to the file with a certificate authority database
   (provides the scope -> inspector map etc.).

## 2.4 Entity creation commands

### 2.4.1 uer/service/inspector creation

For this operation, you must run the following on the command line:

`python -m cmd.create --[option]`

1. For user creation: `--user`;
2. For service creation `--service`;
3. For inspector creation `--inspector`. Additionally, you must specify the option
   `--scope <scope: string>` - the type of personal data that the inspector verifies.

There are also optional arguments:

1. `--output <path-to-file>` -- path to the file of the entity. If it is not provided,
   the default path will be used.
2. `--key <path-to-binary-key-file>` -- path to the key file (binary file, at least 32 bytes
   for user and service, at least 64 bytes for inspector).
3. `--auth <path-to-auth>` -- path to the file with a certificate authority database
   (provides the scope -> inspector map etc.).

### 2.4.2 Certificate authority creation

For this operation, you must run the following on the command line:

`python -m cmd.auth`

There are also optional arguments:
1. `--output <path-to-file>` -- path to the file of the entity. If it is not provided,
   the default path will be used.

# 3. Command-line protocol emulation example

```
# create certificate authority file
python -m cmd.auth -v

# create user file and write down in data/usr1
python -m cmd.create --user --output data/usr1 

# create service file
python -m cmd.create --service --output data/src

# create inspector file
python -m cmd.create --inspector --scope "passport" --output data/insp

# register user personal data with the service
python -m cmd.insp --inspector data/insp --add --uid 1 --secdata "Ivanov Ivan Ivanovich"

# The service requests user personal data
 python -m cmd.src --form --uid 1 --scope "passport" --due 2020-10-10

# The user validates the request signature (optional)
python -m cmd.usr --check --request data/request --user data/usr1

# The user generates a blob
python -m cmd.usr --form --user data/usr1 --request data/request --secdata "Ivanov Ivan Ivanovich"

# The inspector verifies the blob
python -m cmd.insp --verify --blob data/blob

# The service verifies the response is correct
python -m cmd.src --check --response data/response

# If the user forms a blob with invalid personal data ...
python -m cmd.usr --form --user data/usr1 --request data/request --secdata "Ivanov Ivan Petrovich" --output data/fake_blob

python -m cmd.insp --verify --blob data/fake_blob --output data/response_for_fake

# then the response will not pass the inspector verification step
python -m cmd.src --check --response data/response_for_fake
```

### Russian

Реализация X-протокола на языке python 3.

# 0. Пререквизиты для запуска/тестирования

Модули pygost, datetime, json 
Python: версия языка >= 3.5

# 1. Запуск тестов

Для запуска тестов необходимо в командной строке выполнить следующую команду:

`python -m unittest discover`

# 2. Утилиты командной строки 

Во всех приведенных ниже командах можно использовать дополнительный ключ
`--verbose` для выведения дополнительной информации на экран. 
Все пути "по умолчанию" находятся в файле default.py.

## 2.1 Команды Сервиса

### 2.1.1 Формирование Request

Для данной операции необходимо в командной строке выполнить:

`python -m cmd.src --form --uid <user-id:int> --scope <data-scope:str> --due <date>`

Опциональными являются дополнительные аргументы:
1. `--output <path-to-file>` -- путь до файла (с именем файла включительно), куда
сохранить сформированный request, по умолчанию путь = `data/request`.
2. `--service <path-to-service>` -- путь до файла с ключами и иной информации о
   сервисе, по умолчанию путь = `data/src`, можно изменить в файле default.py
   или передать в явном виде.
3. `--auth <path-to-auth>` -- путь до файла с базой данных центра аутентификации
   (задает отображение scope -> inspector и т.д.)

Например:

`python -m cmd.src --form --uid 123 --scope "паспортные данные" --due 2099-01-01`

**Дата пишется в формате YYYY-MM-DD.**

### 2.1.2 Проверка подписи блоба (пришедшего от пользователя)

Для данной операции необходимо в командной строке выполнить:

`python -m cmd.src --check --blob <path-to-blob>`

Опциональными являются дополнительные аргументы:

1. `--service <path-to-service>` -- путь до файла с ключами и иной информации о
   сервисе, по умолчанию путь = `data/src`, можно изменить в файле default.py
   или передать в явном виде.
2. `--auth <path-to-auth>` -- путь до файла с базой данных центра аутентификации
   (задает отображение scope -> inspector и т.д.), по умолчанию путь `data/AUTH`.


### 2.1.3 Проверка ответа инспектора 

Для данной операции необходимо в командной строке выполнить:

`python -m cmd.src --check --response <path-to-response>`

Опциональными являются дополнительные аргументы:

1. `--service <path-to-service>` -- путь до файла с ключами и иной информации о
   сервисе, по умолчанию путь = `data/src`, можно изменить в файле default.py
   или передать в явном виде.
2. `--auth <path-to-auth>` -- путь до файла с базой данных центра аутентификации
   (задает отображение scope -> inspector и т.д.)

Команда проверяет подпись инспектора, а также ответ-подтверждение (являются ли
предоставленные в блобе зашифрованные персональные данные корректными).

## 2.2 Команды пользователя

### 2.2.1 Формирование Blob 

Для данной операции необходимо в командной строке выполнить:

`python -m cmd.usr --form --request <path-to-request>`

Опциональными являются дополнительные аргументы:
1. `--output <path-to-file>` -- путь до файла (с именем файла включительно), куда
сохранить сформированный blob, по умолчанию путь = `data/blob`.
2. `--secdata <personal data>` -- персональные данные пользователя,
   соответствующие запрошенному request. Если персональные данные не переданы
   при вызове скрипта, то они будут запрошены (вместе с выводом информации об ID
   Сервиса, типе запрашиваемых персональных данных и датой, до которой требуются
   персональные данные.
2. `--user <path-to-user>` -- путь до файла с ключами и иной информации о
   пользователе, по умолчанию путь = `data/usr`, можно изменить в файле default.py
   или передать в явном виде.
3. `--auth <path-to-auth>` -- путь до файла с базой данных центра аутентификации
   (задает отображение scope -> inspector и т.д.)

Например:

`python -m cmd.usr --form --request data/request --secdata "Иванов Иван Иванович"` 

### 2.2.2 Проверка Request (подпись)

Для данной операции необходимо в командной строке выполнить:

`python -m cmd.usr --check --request <path-to-request>`

Опциональными являются дополнительные аргументы:

1. `--user <path-to-user>` -- путь до файла с ключами и иной информации о
   пользователе, по умолчанию путь = `data/src`, можно изменить в файле default.py
   или передать в явном виде.
2. `--auth <path-to-auth>` -- путь до файла с базой данных центра аутентификации
   (задает отображение scope -> inspector и т.д.)

## 2.3 Команды Инспектора

### 2.3.1 Верификация Blob 

Для данной операции необходимо в командной строке выполнить:

`python -m cmd.insp --verify --blob <path-to-blob>`

Опциональными являются дополнительные аргументы:
1. `--output <path-to-file>` -- путь до файла (с именем файла включительно), куда
сохранить сформированный response, по умолчанию путь = `data/response`.
2. `--inspector <path-to-inspector>` -- путь до файла с ключами и иной информации о
   инспекторе, по умолчанию путь = `data/insp`, можно изменить в файле default.py
   или передать в явном виде.
3. `--auth <path-to-auth>` -- путь до файла с базой данных центра аутентификации
   (задает отображение scope -> inspector и т.д.)

Например:

`python -m cmd.insp --verify --blob data/blob` 

### 2.3.2 Добавление персональных данных пользователя 

Для данной операции необходимо в командной строке выполнить:

`python -m cmd.insp --add --uid <user-id:int> --secdata <data : str>`

Опциональными являются дополнительные аргументы:

1. `--inspector <path-to-inspector>` -- путь до файла с ключами и иной информации о
   инспекторе, по умолчанию путь = `data/insp`, можно изменить в файле default.py
   или передать в явном виде.
2. `--auth <path-to-auth>` -- путь до файла с базой данных центра аутентификации
   (задает отображение scope -> inspector и т.д.)

## 2.4 Команды создания сущностей

### 2.4.1 Создание пользователя/сервиса/инспектора

Для данной операции необходимо в командной строке выполнить:

`python -m cmd.create --[option]`

1. Для создания пользователя: `--user`
2. Для создания сервиса `--service`
3. Для создания инспектора `--inspector`. Дополнительно необходимо указать опцию
   `--scope <scope:string>` - тип персональных данных, которые проверяет данный
   инспектор.

Опциональными являются следующие аргументы:
1. `--output <path-to-file>` - путь для сохранения файла сущности. Если путь не
   указан, то используется путь по умолчанию.
2. `--key <path-to-binary-key-file>` - путь до файла с ключами (двоичный файл,
для пользователя и сервиса длины минимум 32 байта, для инспектора - минимум 64
байта).
3. `--auth <path-to-auth>` - путь до файла центра аутентификации. Если путь не
   указан, то используется путь по умолчанию.

### 2.4.2 Создание центра аутентификации

Для данной операции необходимо в командной строке выполнить:

`python -m cmd.auth`

Опциональными являются следующие аргументы:
1. `--output <path-to-file>` - путь для сохранения файла сущности. Если путь не
   указан, то используется путь по умолчанию.

# 3. Пример эмуляции протокола из командной строки

```
# создаем файл центра Аутентификации
python -m cmd.auth -v

# создаем файл пользователя и записываем в data/usr1
python -m cmd.create --user --output data/usr1 

# создаем файл сервиса
python -m cmd.create --service --output data/src

# создаем файл инспектора
python -m cmd.create --inspector --scope "паспортные данные" --output data/insp

# регистрируем персональные данные пользователя у инспектора
python -m cmd.insp --inspector data/insp --add --uid 1 --secdata "Иванов Иван Иванович"

# Сервис запрашивает персональные данные у пользователя
 python -m cmd.src --form --uid 1 --scope "паспортные данные" --due 2020-10-10

# Пользователь проверяет подпись под запросом (опционально)
python -m cmd.usr --check --request data/request --user data/usr1

# Пользователь формирует блоб
python -m cmd.usr --form --user data/usr1 --request data/request --secdata "Иванов Иван Иванович"

# Инспектор проверяет блоб
python -m cmd.insp --verify --blob data/blob

# Сервис проверяет, что ответ корректен
python -m cmd.src --check --response data/response

# Если пользователь формирует блоб с неправильными персональными данными ...
python -m cmd.usr --form --user data/usr1 --request data/request --secdata "Иванов Иван Петрович" --output data/fake_blob

python -m cmd.insp --verify --blob data/fake_blob --output data/response_for_fake

# то ответ не пройдет проверку пользователя
python -m cmd.src --check --response data/response_for_fake
```
 
