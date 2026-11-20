# Доставка - demo-сервис (BE-016)

Demo-сервис, демонстрирующий вход через Vault по OAuth 2.0, получение
разрешённых данных и pull-синхронизацию изменений.

## Структура

- `backend/` - Go-сервис: OAuth Authorization Code + PKCE, получение
  разрешённых полей и изменений; отдаёт и простые
  HTML-страницы для показа.
- `frontend/` - папка для интерфейса demo-сервиса;
  сейчас заглушка.
- `docker-compose.yml` - запуск сервиса в контейнере; `backend/Dockerfile`
  собирает образ.

## Предусловия

1. Запущен стек PDV: `docker compose up -d --build` в папке `project/`.
2. В `project/backend/oauth-clients.example.json` есть клиент `delivery`
   с redirect_uri `http://localhost:8090/callback`.
3. В PDV зарегистрирован пользователь, в Vault заполнены поля
   (`full_name`, `email`, `phone`, `address`).

## Запуск (напрямую)

```powershell
cd backend
go run .
```

## Запуск (Docker)

```powershell
docker compose up --build
```

Сервис: http://localhost:8090

## Демо-сценарий

1. Откройте http://localhost:8090 → «Войти через Vault».
2. На экране согласия PDV разрешите запрошенные поля. Сервис получит
   access-токен и покажет данные из Vault.
3. Чтобы работала синхронизация, в PDV включите для Delivery тип
   «Синхронизация» (consent access_type = sync):
   в веб-интерфейсе PDV это можно сделать через API, например:

   ```powershell
   # session cookie пользователя PDV - из DevTools; id согласия - из GET /consents
   curl.exe -b "pdv_session=<cookie>" -X PATCH http://localhost:8080/consents/<id> `
     -H "Content-Type: application/json" `
     -d '{\"scopes\":[\"full_name\",\"email\",\"phone\",\"address\"],\"access_type\":\"sync\"}'
   ```

4. Измените поле в Vault (например, адрес), затем обновите страницу
   сервиса - блок «Синхронизация» покажет изменённое поле с новой версией.
5. Отзовите согласие в PDV («Подключённые сервисы» → «Отозвать доступ») -
   сервис получит 403 и покажет сообщение об отзыве.

## Настройка

Переменные окружения: `PORT`, `VAULT_URL`, `CLIENT_ID`, `REDIRECT_URI`,
`SCOPES` - см. `.env.example`. Токен хранится только в HttpOnly cookie
сервиса и не попадает в HTML.
