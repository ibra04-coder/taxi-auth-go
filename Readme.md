# Taxi Auth Middleware (Go)

Легковесная библиотека для децентрализованной авторизации в
микросервисах на Go.\
Разработана для экосистемы такси-проекта как замена или дополнение к
Laravel Passport.

------------------------------------------------------------------------

## 📌 Описание

В микросервисной архитектуре обращение к центральному сервису
авторизации (например, Laravel API) на каждый запрос создаёт лишнюю
нагрузку и увеличивает задержки.

**Taxi Auth Middleware** реализует подход **Stateless Authentication**,
при котором каждый микросервис самостоятельно валидирует JWT-токен без
обращения к центральному сервису.

------------------------------------------------------------------------

## 🚀 Основные возможности

-   ✅ Валидация RSA (RS256) подписей
-   ✅ Поддержка нескольких публичных ключей одновременно
-   ✅ Извлечение `user_id (sub)` и `scopes` в контекст запроса
-   ✅ Проверка отозванных токенов через Redis (JTI Blacklist)
-   ✅ Совместимость с любыми фреймворками (Gin, Echo, Fiber, net/http)
-   ✅ Stateless-архитектура без лишних сетевых вызовов

------------------------------------------------------------------------

## 🏗 Как это работает

1.  **Проверка подписи**\
    Микросервис самостоятельно проверяет валидность JWT, используя
    публичные ключи (`oauth-public.key`).

2.  **Мульти-ключи**\
    Поддерживается одновременная работа с токенами от разных сервисов
    (например, `client_api` и `driver_api`).

3.  **Отзыв токенов**\
    Используется Redis Blacklist для мгновенной блокировки токенов при
    логауте.

------------------------------------------------------------------------

## 📦 Установка

``` bash
go get github.com/ibra04-coder/taxi-auth-go
```

------------------------------------------------------------------------

## 🔧 Примеры использования

### Использование с Gin

``` go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/redis/go-redis/v9"
    "github.com/ibra04-coder/taxi-auth-go"
    "net/http"
)

func main() {
    // 1. Настраиваем ключи (обычно загружаются из файлов или ENV)
    publicKeys := map[string]string{
        "client": "-----BEGIN PUBLIC KEY-----\n...key content...\n-----END PUBLIC KEY-----",
        "driver": "-----BEGIN PUBLIC KEY-----\n...key content...\n-----END PUBLIC KEY-----",
    }

    // 2. Опционально: Настройка Redis для проверки отзыва токенов
    rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
    checker := auth.NewRedisChecker(rdb, "blacklist:") // префикс ключей в Redis

    // 3. Создаем Middleware
    authMid, err := auth.NewAuthMiddleware(publicKeys, checker)
    if err != nil {
        panic(err)
    }

    r := gin.Default()

    // 4. Применяем Middleware к группе роутов
    protected := r.Group("/api/v1")
    protected.Use(func(c *gin.Context) {
        authMid.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            c.Request = r
            c.Next()
        })).ServeHTTP(c.Writer, c.Request)
    })

    // 5. Доступ к данным в обработчике
    protected.GET("/orders", func(c *gin.Context) {
        userID := auth.GetUserID(c.Request.Context())
        
        // Проверка прав (scopes)
        if !auth.HasScope(c.Request.Context(), "view-orders") {
            c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
            return
        }

        c.JSON(200, gin.H{"user_id": userID})
    })

    r.Run(":8080")
}
```

------------------------------------------------------------------------

## 🔐 Отзыв токенов (Revocation)

Laravel должен записать `jti` токена в Redis в формате:

    blacklist:<jti>

Если ключ существует --- запрос отклоняется с `401 Unauthorized`.

------------------------------------------------------------------------

## 🛠 Доступные хелперы

``` go
auth.GetUserID(ctx)
auth.GetScopes(ctx)
auth.HasScope(ctx, "admin")
```

------------------------------------------------------------------------

## 🧠 Архитектурные преимущества

-   Отсутствие сетевых вызовов к auth-сервису
-   Горизонтальное масштабирование без узкого места
-   Минимальная задержка обработки запроса
-   Простая интеграция в существующие сервисы

------------------------------------------------------------------------

## 📄 Лицензия

MIT
