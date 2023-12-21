package responses

import (
	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserResponseData struct {
	Id       primitive.ObjectID `json:"id"`
	Username string             `json:"username"`
	Email    string             `json:"email"`
	// Other fields...
}

type UserResponse struct {
	Status  int       `json:"status"`
	Message string    `json:"message"`
	Data    *echo.Map `json:"data"`
}
