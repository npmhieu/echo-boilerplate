package utils

import "github.com/go-playground/validator/v10"

// CustomValidator wraps the validator instance
type CustomValidator struct {
	Validator *validator.Validate
}

// Validate implements the echo.Validator interface
func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.Validator.Struct(i)
}
