package handlers

import (
	"github.com/labstack/echo/v4"
	"goapp/src/utils"
	"net/http"
)

func HomeHandler(c echo.Context) error {
	// Use the LoadAssets function from the utils package
	cssFiles, jsFiles, _ := utils.LoadAssets("app")

	data := map[string]interface{}{
		"title":    "Homepage",
		"content":  "This is the homepage content.",
		"cssFiles": cssFiles,
		"jsFiles":  jsFiles,
	}
	return c.Render(http.StatusOK, "homepage", data)
}

func AboutHandler(c echo.Context) error {
	// Use the LoadAssets function from the utils package
	cssFiles, jsFiles, _ := utils.LoadAssets("about")

	data := map[string]interface{}{
		"title":    "About",
		"content":  "This is the about content.",
		"cssFiles": cssFiles,
		"jsFiles":  jsFiles,
	}
	return c.Render(http.StatusOK, "about", data)
}
