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

package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/ibra04-coder/taxi-auth-go"
)

func main() {
	r := gin.Default()

	// 1. Настройка Redis для проверки отозванных токенов (Blacklist)
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	checker := auth.NewRedisChecker(rdb, "blacklist:")

	// 2. Загружаем публичные ключи (в реальности лучше читать из .key файлов или ENV)
	// Ключи должны соответствовать тем, которыми Laravel Passport подписывает токены
	publicKeys := map[string]string{
		"client": os.Getenv("CLIENT_PUBLIC_KEY"),
		"driver": os.Getenv("DRIVER_PUBLIC_KEY"),
	}

	authMid, err := auth.NewAuthMiddleware(publicKeys, checker)
	if err != nil {
		panic("Failed to init auth middleware: " + err.Error())
	}

	api := r.Group("/api/v1")

	api.Use(adaptToGin(authMid.Handler))

	api.GET("/me", func(c *gin.Context) {
		ctx := c.Request.Context()
		c.JSON(200, gin.H{
			"user_id":   auth.GetUserID(ctx),
			"user_type": auth.GetUserType(ctx),
			"client_id": auth.GetClientID(ctx),
		})
	})

	clientRoutes := api.Group("/client")
	clientRoutes.Use(adaptToGin(auth.Only("client")))
	{
		clientRoutes.GET("/orders", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "Список заказов клиента"})
		})
	}
s
	driverRoutes := api.Group("/driver")
	driverRoutes.Use(adaptToGin(auth.Only("driver")))
	{
		driverRoutes.POST("/status", func(c *gin.Context) {
			if !auth.HasScope(c.Request.Context(), "update-status") {
				c.JSON(403, gin.H{"error": "Нет прав для обновления статуса"})
				return
			}
			c.JSON(200, gin.H{"message": "Статус водителя обновлен"})
		})
	}

	r.Run(":8080")
}

func adaptToGin(handler func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Request = r
			c.Next()
		})).ServeHTTP(c.Writer, c.Request)
	}
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
