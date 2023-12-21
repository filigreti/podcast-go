package routes

import (
	"net/http"

	"github.com/filigreti/podcast-backend/controllers"
	"github.com/filigreti/podcast-backend/middleware"
	"github.com/labstack/echo/v4"
)

func UserRoute(e *echo.Echo) {
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Great!, Nothing to see here")
	})
	e.POST("/register", controllers.CreateUser)
	e.POST("/login", controllers.UserLogin)
	e.GET("/user", controllers.GetUser, middleware.TokenMiddleware)
	e.GET("/verify-email/:token", controllers.VerifyEmail)
}
