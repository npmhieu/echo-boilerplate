package routes

import (
	"goapp/src/middleware"
	"net/http"

	"github.com/labstack/echo/v4"
)

// RegisterAuthAPIRoutes registers the routes for the API
func RegisterAuthAPIRoutes(e *echo.Echo) {
	apiGroup := e.Group("/api/auth")
	apiGroup.GET("/me", middleware.JWTMiddleware(GetCurrentUser))
}

// GetCurrentUser handles the /api/tasks route
func GetCurrentUser(c echo.Context) error {
	user := c.Get("user").(map[string]interface{}) // Retrieve user info from context
	return c.JSON(http.StatusOK, user)
}
