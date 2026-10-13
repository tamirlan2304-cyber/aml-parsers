# Phishing parsers

Источники хранятся в разных Parquet-файлах:

```text
phishing/scamsniffer.parquet
phishing/chainabuse.parquet
```

## Файлы

- `scamsniffer_parser.py` — открытый JSON ScamSniffer;
- `chainabuse_parser.py` — асинхронная загрузка обращений Chainabuse;
- `chainabuse_incremental.py` — ежедневное обновление уже существующей таблицы;
- `phishing_common.py` — схемы, нормализация и валидация;
- `run_and_upload.py` — обновление двух объектов в S3;
- `save_local.py` — локальное сохранение Parquet;
- `debug_table.py` — вывод таблиц в консоль.

## Схема Chainabuse

```text
wallet_address  string, not null
network         string, not null
domain          string, not null
report_date     date32, nullable
report_id       string, not null
report_count    int64, not null
```

`report_id` — UUID из адреса страницы вида
`https://chainabuse.com/report/<report_id>`. Одна строка соответствует одному
уникальному `wallet_address`. `report_id` хранит первое по времени обращение,
`report_count` — количество разных обращений с этим адресом, а `report_date` —
дату последнего обращения. Все EVM-сети приводятся к `Ethereum`, домены
объединяются через `; `.

## Как ускорен Chainabuse

Парсер больше не запускает Chrome и не открывает карточки по одной. Он обращается
к GraphQL endpoint, который использует сам сайт, получает по 50 обращений за
запрос и параллельно выполняет несколько запросов через асинхронный Playwright.
Вход в браузере не нужен.

Основные настройки:

```dotenv
CHAINABUSE_ENABLED=True
CHAINABUSE_CONCURRENCY=8
CHAINABUSE_REQUEST_RETRIES=4
CHAINABUSE_PAGE_TIMEOUT_SECONDS=120
CHAINABUSE_MAX_PAGES=0
CHAINABUSE_ALLOW_PARTIAL=False
```

Увеличивать `CHAINABUSE_CONCURRENCY` стоит осторожно: слишком большое значение
может вызвать ограничение частоты запросов со стороны сайта. Ошибочные запросы
повторяются с увеличивающейся задержкой.

## Чекпоинты

При полном обходе накопительный checkpoint сохраняется после каждых 500 API-
страниц (до 25 000 обращений):

```text
chainabuse_checkpoint_page_00000500_items_00000001-00025000.parquet
```

Настройки:

```dotenv
CHAINABUSE_CHECKPOINT_INTERVAL_PAGES=500
CHAINABUSE_CHECKPOINT_DIR=chainabuse_checkpoints
CHAINABUSE_RESUME=True
```

После `Ctrl+C` завершённый диапазон сохраняется и следующий полный запуск
продолжается с checkpoint. После изменения ключа на адрес используется checkpoint
версии 3. Старые checkpoint не подходят новой схеме, поэтому первый полный запуск
начинает загрузку заново. После успешной записи нового checkpoint файлы с меньшим
номером страницы автоматически удаляются, поэтому в каталоге остаётся только
последний актуальный checkpoint.

Старый S3-файл Chainabuse с прежней схемой не объединяется в полном pipeline.
После успешного полного парсинга он заменяется новой таблицей. Инкрементальный
модуль умеет преобразовать предыдущую пятиколоночную схему, сгруппировав её по
адресу.

## Ежедневное обновление

Файл `chainabuse_incremental.py` принимает уже загруженную из S3 `pyarrow.Table`:

```python
from chainabuse_incremental import build_incremental_table

updated_table = build_incremental_table(existing_s3_table)
```

Таблица сортируется по `report_date`. Парсер берёт последнюю обработанную дату,
вычитает пять дней и загружает Chainabuse от самых новых обращений назад,
включительно до рассчитанной даты. Например, для даты `2026-10-29` нижняя
граница будет `2026-10-24`.

Чтобы пятидневное перекрытие не увеличивало `report_count` повторно, UUID
обработанных за этот диапазон обращений сохраняются в metadata возвращаемого
Parquet. При записи в S3 необходимо сохранять именно таблицу, возвращённую
`build_incremental_table`, вместе с её schema metadata.

Локальный запуск инкрементального режима:

```powershell
..\.venv\Scripts\python.exe chainabuse_incremental.py input.parquet output.parquet
```

## Запуск

Установка зависимостей:

```powershell
..\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Быстрая проверка двух API-страниц (до 100 обращений), без S3 и checkpoint:

```powershell
..\.venv\Scripts\python.exe chainabuse_parser.py --max-pages 2 --allow-partial
```

Вывод первых строк в консоль:

```powershell
..\.venv\Scripts\python.exe debug_table.py --source chainabuse --max-pages 2 --allow-partial --limit 20
```

Полный запуск и обновление S3:

```powershell
..\.venv\Scripts\python.exe run_and_upload.py --source chainabuse
```

Локальное сохранение:

```powershell
..\.venv\Scripts\python.exe save_local.py --source chainabuse
```

В production `CHAINABUSE_ALLOW_PARTIAL` должен оставаться равным `False`.
