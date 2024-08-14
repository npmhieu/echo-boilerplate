// routes/routes.go
package routes

import (
	"github.com/labstack/echo/v4"
	"goapp/src/handlers" // Import the package where LoadAssets is defined
)

func RegisterRoutes(e *echo.Echo) {
	e.GET("/", handlers.HomeHandler)
	e.GET("/about", handlers.AboutHandler)
}
