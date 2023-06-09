package user

import (
	"github.com/aldyN25/go-fiber-rest/app/models"
	gormdb "github.com/aldyN25/go-fiber-rest/pkg/gorm.db"
	"github.com/aldyN25/go-fiber-rest/pkg/utils/constants"
	"github.com/aldyN25/go-fiber-rest/pkg/utils/converter"
	"github.com/aldyN25/go-fiber-rest/pkg/utils/validator"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

func CreateUser(c *fiber.Ctx) error {
	userRequest := new(models.UserReq)

	if err := c.BodyParser(&userRequest); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": err.Error(),
		})
	}

	errors := validator.ValidateRequest(userRequest)
	if errors != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errors)
	}

	db, err := gormdb.GetInstance()
	if err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userRequest.Password), bcrypt.DefaultCost)

	if err != nil {
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"status":  constants.STATUS_FAIL,
			"message": "error",
			"data":    err.Error(),
		})
	}

	var user = models.User{
		Email:    userRequest.Email,
		Password: string(hashedPassword),
	}

	db.Create(&user)

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status":  constants.STATUS_SUCCESS,
		"message": "user created",
		"data":    user.ToUserRes(),
	})
}

func GetAllUsers(c *fiber.Ctx) error {
	db, err := gormdb.GetInstance()
	if err != nil {
		return err
	}

	users := []models.User{}
	db.Find(&users)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  constants.STATUS_SUCCESS,
		"message": "Ok",
		"data":    converter.MapUserToUserRes(users),
	})
}
