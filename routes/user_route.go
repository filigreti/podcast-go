package routes

import (
	"github.com/filigreti/podcast-backend/controllers"
	"github.com/filigreti/podcast-backend/middleware"
	"github.com/labstack/echo/v4"
)

func UserRoute(e *echo.Echo) {
	e.POST("/register", controllers.CreateUser)
	e.POST("/login", controllers.UserLogin)
	e.GET("/user", controllers.GetUser, middleware.TokenMiddleware)
	e.GET("/verify-email/:token", controllers.VerifyEmail)
}
