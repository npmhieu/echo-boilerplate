package main

import (
	"github.com/go-playground/validator/v10"
	_ "github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"goapp/src/config"
	"goapp/src/routes"
	"goapp/src/utils"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		panic("Error loading .env file")
	}
	utils.InitSendMail()
	// Initialize database connection
	config.ConnectDatabase()

	e := echo.New()
	// Register the custom validator
	e.Validator = &utils.CustomValidator{Validator: validator.New()}
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Set custom renderer
	e.Renderer = utils.RenderTemplate()

	// Set output build folder of webpack
	e.Static("/build", "public/build")

	// Any static files
	e.Static("/static", "static")

	routes.RegisterRoutes(e)
	routes.RegisterAPIRoutes(e)
	routes.RegisterAuthAPIRoutes(e)

	e.Logger.Fatal(e.Start(":8080"))
}
