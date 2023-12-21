package main

import (
	"github.com/filigreti/podcast-backend/configs"
	"github.com/filigreti/podcast-backend/routes"
	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
	configs.ConnectDB()
	routes.UserRoute(e)
	e.Logger.Fatal(e.Start(":6000"))

}
