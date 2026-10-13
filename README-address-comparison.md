# Сравнение локального Parquet с PostgreSQL

`compare_parquet_postgres.py` находит строки входного Parquet, для которых адреса
отсутствуют в PostgreSQL. Скрипт не создаёт таблиц и не записывает ничего в базу:
соединение открывается с `default_transaction_read_only=on` и выполняет только
`SELECT`.

## Подготовка

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-address-comparison.txt
```

Откройте `compare_parquet_postgres.py` и заполните блок `CONFIGURATION` в начале
файла: `DATABASE_URL`, пути к Parquet, имя таблицы и адресные колонки. Аргументов
командной строки у скрипта нет.

Пользователь базы должен иметь только `CONNECT` и `SELECT` на сравниваемую таблицу.
При `CASE_INSENSITIVE_COMPARISON = False` на колонке PostgreSQL должен быть B-tree
индекс. Например, если сравнение идёт по `normalized_address`, индекс проверяет
администратор базы:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS addresses_normalized_address_idx
ON public.addresses (normalized_address);
```

Не выполняйте этот `CREATE INDEX` самостоятельно на production без согласования:
сам скрипт индексы не создаёт.

## Запуск

Пример для уже существующего файла в этой папке:

```powershell
.\.venv\Scripts\python.exe .\compare_parquet_postgres.py
```

Основной выходной файл содержит **полные исходные строки** Parquet, а не только
адресную колонку: их проще затем исследовать или загрузить в другой процесс.
`--matched-output` необязателен. Рядом с основным результатом создаётся JSON-отчёт
с числом строк, пачек и временем выполнения.

Все строки и все адреса из Parquet проверяются без удаления дублей или пустых значений:
это предполагает, что входной адресный столбец уже валиден и уникален.

Скрипт не перезаписывает существующий результат. Для сознательной перезаписи укажите
`OVERWRITE_OUTPUTS = True` в блоке конфигурации.

В блоке конфигурации есть переключатель:

```python
CASE_INSENSITIVE_COMPARISON = False
```

Оставляйте `False` для Tron и других Base58-сетей: `TAbc...` и `Tabc...` — разные
значения. Для EVM-кошельков установите `True`: тогда сравнение считает `0xAbC...` и
`0xabc...` одним адресом. В этом режиме запрос использует `LOWER(колонка)`, поэтому
обычный B-tree индекс по исходной колонке может не использоваться. Для быстрого поиска
нужен функциональный индекс, созданный администратором БД:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS addresses_lower_address_idx
ON public.addresses (LOWER(normalized_address));
```

Пачка по умолчанию — 10 000 строк и один запрос к БД на пачку. Начните с неё на
read-replica. На primary не запускайте несколько копий скрипта параллельно: индексные
чтения могут вытеснить из cache полезные production-страницы.
