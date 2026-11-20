# Frontend demo-сервиса «Доставка»

Папка для задачи FE-007 «Сверстать интерфейс demo-сервиса "Доставка"»
(Никита Комаров, Sprint 5). Здесь размещается вёрстка интерфейса
сервиса; backend находится в `../backend`.

Контракты, на которые опирается интерфейс:

- `GET /services/consent` — статус согласия (Bearer-токен OAuth);
- `GET /services/data?fields=...` — разрешённые поля и значения;
- `GET /services/sync?since=...` — изменения полей после момента `since`
  (требуется согласие типа sync).

Полное описание — в Swagger UI PDV: http://localhost:8080/swagger/index.html
(раздел `services` и `sync`).
