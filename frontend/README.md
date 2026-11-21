# Frontend demo-сервиса «Доставка»

Интерфейс demo-сервиса «Доставка» отдаётся backend по адресу
http://localhost:8090. В `index.html`, `styles.css` и `app.js` находятся шаблон,
стили и проверка выбора полей. Копии в `../backend/` встраиваются в
исполняемый файл. После изменения нужно обновить обе копии. Тест
`TestFrontendTemplateMatchesEmbeddedPage` проверяет их совпадение.

Пользователь выбирает поля на странице. Backend формирует OAuth-запрос с PKCE,
обменивает код и обращается к API Vault. Токен хранится в HttpOnly-cookie
сервиса и не передаётся JavaScript-коду страницы.

Контракты, на которые опирается интерфейс:

- `GET /services/consent` — статус согласия (Bearer-токен OAuth);
- `GET /services/data?fields=...` — разрешённые поля и значения;
- `GET /services/sync?since=...` — изменения полей после момента `since`
  (требуется согласие типа sync).

Полное описание — в Swagger UI PDV: http://localhost:8080/swagger/index.html
(раздел `services` и `sync`).
