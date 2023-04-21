package auth

import (
	"github.com/aldyN25/go-fiber-rest/app/models"
	userRepository "github.com/aldyN25/go-fiber-rest/app/repository/user"
	"github.com/aldyN25/go-fiber-rest/pkg/jwt"
	"github.com/aldyN25/go-fiber-rest/pkg/utils/constants"
	"github.com/aldyN25/go-fiber-rest/pkg/utils/validator"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

func Login(c *fiber.Ctx) error {
	userRequest := new(models.UserReq)

	_ = c.BodyParser(&userRequest)

	errors := validator.ValidateRequest(userRequest)
	if errors != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{
			"status":  constants.STATUS_FAIL,
			"message": "request body invalid",
			"error":   errors,
		})
	}

	user := &models.User{}
	userRepository.GetUserByEmail(userRequest.Email, user)

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userRequest.Password))

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  constants.STATUS_FAIL,
			"message": "credentials invalid",
			"error":   err.Error(),
		})
	}

	accessToken, err := jwt.GenerateToken(user)
	if err != nil {
		return err
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"user":         user.ToUserRes(),
		"accessToken":  accessToken,
		"refreshToken": "",
	})
}

func Register(c *fiber.Ctx) error {
	userRequest := new(models.UserReq)

	_ = c.BodyParser(&userRequest)

	errors := validator.ValidateRequest(userRequest)
	if errors != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{
			"status":  constants.STATUS_FAIL,
			"message": "request body invalid",
			"error":   errors,
		})
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(userRequest.Password), bcrypt.DefaultCost)
	user := &models.User{
		Email:    userRequest.Email,
		Password: string(hashedPassword),
	}
	err := userRepository.GetUserByEmail(userRequest.Email, user)
	if err == nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{
			"status":  constants.STATUS_FAIL,
			"message": "email is already exists",
			"error":   "",
		})
	}

	userRepository.CreateUser(user)

	accessToken, err := jwt.GenerateToken(user)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"user":         user.ToUserRes(),
		"accessToken":  accessToken,
		"refreshToken": "",
	})
}
