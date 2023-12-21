package main

import (
	"github.com/filigreti/podcast-backend/configs"
	"github.com/filigreti/podcast-backend/routes"
	"github.com/labstack/echo/v4"
)

func init() {
	// Initialize MongoDB first
	configs.ConnectDB()
	configs.ConnectRedis()
}
func main() {
	e := echo.New()
	routes.UserRoute(e)
	e.Logger.Fatal(e.Start(configs.GetEnv("BASE_URL")))

}
