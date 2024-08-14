package utils

import (
	"github.com/flosch/pongo2/v6"
	"github.com/labstack/echo/v4"
	"io"
)

// TemplateRenderer is a custom renderer for Echo using Pongo2
type TemplateRenderer struct {
	templates map[string]*pongo2.Template
}

// Render method implements the Echo Renderer interface
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	tmpl, ok := t.templates[name]
	if !ok {
		return echo.ErrNotFound
	}

	// Create a Pongo2 context from the data
	var pongoContext pongo2.Context
	if data != nil {
		if contextData, ok := data.(map[string]interface{}); ok {
			pongoContext = contextData
		}
	}

	// Execute the template with the given context
	return tmpl.ExecuteWriter(pongoContext, w)
}

// RenderTemplate initializes and returns a new TemplateRenderer
func RenderTemplate() *TemplateRenderer {
	// Register Pongo2 templates
	templates := map[string]*pongo2.Template{
		"about":    pongo2.Must(pongo2.FromFile("views/about.html")),
		"homepage": pongo2.Must(pongo2.FromFile("views/home.html")),
	}

	return &TemplateRenderer{
		templates: templates,
	}
}
