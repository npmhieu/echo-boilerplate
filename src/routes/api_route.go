package routes

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// RegisterAPIRoutes registers the routes for the API
func RegisterAPIRoutes(e *echo.Echo) {
	apiGroup := e.Group("/api")
	apiGroup.GET("/tasks", GetTasksHandler)
}

// GetTasksHandler handles the /api/tasks route
func GetTasksHandler(c echo.Context) error {
	tasks := []string{"Task 1", "Task 2", "Task 3"}
	return c.JSON(http.StatusOK, tasks)
}
