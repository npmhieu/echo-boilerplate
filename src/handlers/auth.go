package handlers

import (
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"goapp/src/config"
	"goapp/src/models"
	"goapp/src/utils"
	"net/http"
	"time"
)

func Register(c echo.Context) error {
	user := new(models.User)
	if err := c.Bind(user); err != nil {
		return err
	}

	// Hash the password
	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to hash password"})
	}
	user.Password = hashedPassword

	// Save the user in the database
	result := config.DB.Create(user)
	if result.Error != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create user"})
	}

	// Generate a JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":    user.Email,
		"fullName": user.FullName,
		"roleMask": user.RoleMask,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate token"})
	}

	return c.JSON(http.StatusOK, map[string]string{"token": tokenString})
}

func Login(c echo.Context) error {
	user := new(models.User)
	if err := c.Bind(user); err != nil {
		return err
	}

	// Find the user by email
	storedUser := models.User{}
	result := config.DB.Where("email = ?", user.Email).First(&storedUser)
	if result.Error != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid email or password"})
	}

	// Check the password
	if !utils.CheckPasswordHash(user.Password, storedUser.Password) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid email or password"})
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":    storedUser.Email,
		"fullName": storedUser.FullName,
		"roleMask": storedUser.RoleMask,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate token"})
	}

	return c.JSON(http.StatusOK, map[string]string{"token": tokenString})
}
