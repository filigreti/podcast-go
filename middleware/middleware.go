package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/filigreti/podcast-backend/configs"
	"github.com/labstack/echo/v4"
)

// TokenMiddleware is a middleware function to validate JWT tokens.
func TokenMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Get the token from the Authorization header
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return c.JSON(http.StatusUnauthorized, map[string]interface{}{"error": "Unauthorized"})
		}

		// Check if the Authorization header has the "Bearer" prefix
		parts := strings.Fields(authHeader)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.JSON(http.StatusUnauthorized, map[string]interface{}{"error": "Invalid Authorization header format"})
		}

		tokenString := parts[1]

		// Parse the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Check the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// Replace "your-secret-key" with your actual secret key
			return []byte(configs.GetEnv("SECRET_KEY")), nil
		})

		if err != nil || !token.Valid {
			return c.JSON(http.StatusUnauthorized, map[string]interface{}{"error": "Unauthorized"})
		}

		// Set user ID in the context for further use in the handler
		claims := token.Claims.(jwt.MapClaims)
		userID := claims["sub"].(string)
		c.Set("user", userID)

		return next(c)
	}
}
