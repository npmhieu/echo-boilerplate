package handlers

import (
	"encoding/json"
	"fmt"
	"goapp/src/config"
	"goapp/src/models"
	"goapp/src/utils"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/labstack/echo/v4"
)

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	FullName string `json:"fullName" validate:"required"`
	Phone    string `json:"phone" validate:"omitempty"`
}


func Register(c echo.Context) error {
	// Parse and validate the request body
	req := new(RegisterRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid input"})
	}
	if err := c.Validate(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Validation error"})
	}

	// Hash the password
	hashedPassword, err := utils.HashPassword(req.Password) // bcrypt cost = 12
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to hash password"})
	}

	// Set RoleMask server-side
	roleMask := 1 // Example role mask, you can set this as needed

	// Create the new user
	user := models.User{
		Email:      req.Email,
		Password:   hashedPassword,
		FullName:   req.FullName,
		Phone:      req.Phone,
		RoleMask:   roleMask,
		IsVerified: false,
		Created:    time.Now(),
		Updated:    time.Now(),
	}

	// Save the user to the database
	if result := config.GetDatabase().Create(&user); result.Error != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create user"})
	}

	// Generate a JWT token
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "JWT secret not configured"})
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":    user.Email,
		"fullName": user.FullName,
		"roleMask": user.RoleMask,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate token"})
	}

	// Return the token in the response
	return c.JSON(http.StatusOK, map[string]string{"token": tokenString})
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

func Login(c echo.Context) error {

	// Parse and validate the request body
	req := new(LoginRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid input"})
	}
	if err := c.Validate(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Validation error"})
	}

	// Find the user by email
	storedUser := models.User{}
	result := config.DB.Where("email = ?", req.Email).First(&storedUser)
	if result.Error != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid email or password"})
	}

	// Check the password
	if !utils.CheckPasswordHash(req.Password, storedUser.Password) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid email or password"})
	}

	// Generate a JWT token
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "JWT secret not configured"})
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":    storedUser.Email,
		"fullName": storedUser.FullName,
		"roleMask": storedUser.RoleMask,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate token"})
	}

	return c.JSON(http.StatusOK, map[string]string{"token": tokenString})
}

// ===========================================================
// ********************* Session *********************


type SessionData struct {
	UserID   uint
	Email    string
	RoleMask int
}

func RegisterSession(c echo.Context) error {
	// Parse and validate the request body
	req := new(RegisterRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid input"})
	}
	if err := c.Validate(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Validation error"})
	}

	// Hash the password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to hash password"})
	}

	// Set RoleMask server-side
	roleMask := 1

	// Create the new user
	user := models.User{
		Email:      req.Email,
		Password:   hashedPassword,
		FullName:   req.FullName,
		Phone:      req.Phone,
		RoleMask:   roleMask,
		IsVerified: false, // Người dùng chưa được xác thực
		Created:    time.Now(),
		Updated:    time.Now(),
	}

	// Save the user to the database
	if result := config.GetDatabase().Create(&user); result.Error != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create user"})
	}

	// Tạo session ID
	sessionID := uuid.NewString()
	sessionData := SessionData{
		UserID:   user.ID,
		Email:    user.Email,
		RoleMask: user.RoleMask,
	}

	// Convert session data to JSON
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to marshal session data"})
	}

	// Tạo thời gian hết hạn cho session
	expiresOn := time.Now().Add(72 * time.Hour)

	// Lưu session vào cơ sở dữ liệu
	session := models.SessionUser{
		ID:          sessionID,
		SessionData: sessionJSON,
		ExpiresOn:   expiresOn, 
	}
	
	if result := config.GetDatabase().Create(&session); result.Error != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save session"})
	}

	// Set session ID vào cookie
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Expires:  session.ExpiresOn, 
		HttpOnly: true,
	}
	c.SetCookie(cookie)

	verificationLink := "http://localhost:8080/api/app/verify?session_id=" + sessionID
	emailBody := "Thank you for registering an account. Click on the following link to activate your account: " + verificationLink

	utils.SendEmailAsync(user.Email, "Xác thực tài khoản", emailBody)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":    "Registration successful. Please check your email to verify your account.",
		"session_id": cookie.Value,
		"expires":    cookie.Expires,
	})
}

func LoginSession(c echo.Context) error {

	// Parse and validate the request body
	req := new(LoginRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid input"})
	}
	if err := c.Validate(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Validation error"})
	}

	// Find the user by email
	storedUser := models.User{}
	result := config.DB.Where("email = ?", req.Email).First(&storedUser)
	if result.Error != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid email or password"})
	}

	// Check the password
	if !utils.CheckPasswordHash(req.Password, storedUser.Password) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid email or password"})
	}

	// Tạo session ID
	sessionID := uuid.NewString()

	// Lưu thông tin session
	sessionData := SessionData{
		UserID:   storedUser.ID,
		Email:    storedUser.Email,
		RoleMask: storedUser.RoleMask,
	}

	// Convert session data to JSON
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to marshal session data"})
	}

	expiresOn := time.Now().Add(72 * time.Hour)

	session := models.SessionUser{
		ID:          sessionID,
		SessionData: sessionJSON,
		ExpiresOn:   expiresOn,
		Created:     time.Now(),
		Updated:     time.Now(),
	}

	if result := config.GetDatabase().Create(&session); result.Error != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save session"})
	}

	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Expires:  session.ExpiresOn, 
		HttpOnly: true,
	}
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":    "Login successful",
		"session_id": cookie.Value,
		"expires":    cookie.Expires,
	})
}


func VerifyEmail(c echo.Context) error {
	sessionID := c.QueryParam("session_id")
	fmt.Println(sessionID)
	if sessionID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Missing session ID"})
	}

	session := models.SessionUser{}
	if result := config.GetDatabase().Where("id = ?", sessionID).First(&session); result.Error != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var sessionData SessionData
	if err := json.Unmarshal(session.SessionData, &sessionData); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to parse session data"})
	}

	user := models.User{}
	config.GetDatabase().Where("id = ?", sessionData.UserID).First(&user)
	user.IsVerified = true

	if err := config.GetDatabase().Save(&user).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update user"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Account verified successfully"})
}
