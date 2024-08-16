package routes

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"goapp/src/handlers" // Import the package where LoadAssets is defined
)

// RegisterAPIRoutes registers the routes for the API
func RegisterAPIRoutes(e *echo.Echo) {
	apiGroup := e.Group("/api/app")
	apiGroup.GET("/tasks", GetTasksHandler)
	apiGroup.POST("/register", handlers.Register)
	apiGroup.POST("/login", handlers.Login)
}

// GetTasksHandler handles the /api/tasks route
func GetTasksHandler(c echo.Context) error {
	tasks := []string{"Task 1", "Task 2", "Task 3"}
	return c.JSON(http.StatusOK, tasks)
}
