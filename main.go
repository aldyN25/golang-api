package main

import (
	"fmt"
	"log"

	"github.com/aldyN25/go-fiber-rest/app/configs"
	apiv1 "github.com/aldyN25/go-fiber-rest/routers/api/v1"
	notfound "github.com/aldyN25/go-fiber-rest/routers/exception"
	home "github.com/aldyN25/go-fiber-rest/routers/home"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	app := fiber.New()
	app.Use(recover.New())
	app.Use(logger.New())

	// default here : /
	home.HomeRoutes(app)
	// api route : api/v1
	apiv1.ApiRoutes(app)
	// handle 404
	notfound.Routes(app)

	config := configs.GetInstance()
	listen := fmt.Sprintf(":%v", config.Appconfig.Port)
	log.Fatal(app.Listen(listen))
}
