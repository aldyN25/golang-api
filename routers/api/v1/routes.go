package apiv1

import (
	"github.com/aldyN25/go-fiber-rest/app/configs"
	authController "github.com/aldyN25/go-fiber-rest/app/controllers/auth"
	"github.com/aldyN25/go-fiber-rest/app/controllers/exception"
	noteController "github.com/aldyN25/go-fiber-rest/app/controllers/note"
	userController "github.com/aldyN25/go-fiber-rest/app/controllers/user"
	middleware "github.com/aldyN25/go-fiber-rest/pkg/jwt"
	"github.com/gofiber/fiber/v2"
	jwtware "github.com/gofiber/jwt/v3"
)

func ApiRoutes(app *fiber.App) {
	router := app.Group("/api/v1")

	router.Post("/auth/login", authController.Login)
	router.Post("/auth/register", authController.Register)

	router = router.Group("/", jwtware.New(jwtware.Config{
		SigningKey:   []byte(configs.GetInstance().Jwtconfig.Secret),
		ErrorHandler: exception.ExceptionNotFound,
	}))

	notes := router.Group("/notes", middleware.TokenVerify())

	notes.Get("/", noteController.GetAllNotes)
	notes.Post("/", noteController.CreateNote)
	notes.Get("/:id", noteController.GetNoteById)
	notes.Put("/:id", noteController.UpdateNote)
	notes.Delete("/:id", noteController.DeleteNote)

	users := router.Group("/users", middleware.TokenVerify())
	users.Post("/", userController.CreateUser)
	users.Get("/", userController.GetAllUsers)
}
