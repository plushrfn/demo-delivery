# Frontend demo-сервиса «Доставка»

Интерфейс demo-сервиса «Доставка» отдаётся backend по адресу
http://localhost:8090. В `index.html` хранится HTML-шаблон страницы.
Копия шаблона `../backend/page.html` встраивается в исполняемый файл.
После изменения шаблона нужно обновить обе копии.

Контракты, на которые опирается интерфейс:

- `GET /services/consent` — статус согласия (Bearer-токен OAuth);
- `GET /services/data?fields=...` — разрешённые поля и значения;
- `GET /services/sync?since=...` — изменения полей после момента `since`
  (требуется согласие типа sync).

Полное описание — в Swagger UI PDV: http://localhost:8080/swagger/index.html
(раздел `services` и `sync`).
