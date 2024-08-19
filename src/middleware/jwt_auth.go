package middleware

import (
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
)

// JWTMiddleware validates JWT tokens in the Authorization header
func JWTMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Get the Authorization header
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "Missing or invalid token")
		}

		// Extract the token from the header
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			return echo.NewHTTPError(http.StatusUnauthorized, "Missing or invalid token")
		}

		// Get the JWT secret from environment
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			return echo.NewHTTPError(http.StatusInternalServerError, "JWT secret is not set")
		}

		// Parse the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Ensure that the signing method is HMAC and compatible with HS256
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, echo.NewHTTPError(http.StatusUnauthorized, "Unexpected signing method")
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token: "+err.Error())
		}

		// Store the user claims in context
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Convert jwt.MapClaims to a regular map[string]interface{} and store in context
			claimsMap := map[string]interface{}(claims)
			c.Set("user", claimsMap)
		} else {
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token claims")
		}

		// Continue to the next handler
		return next(c)
	}
}
