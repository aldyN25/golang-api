package home

import (
	"github.com/aldyN25/go-fiber-rest/app/configs"
	"github.com/aldyN25/go-fiber-rest/pkg/utils/constants"
	"github.com/gofiber/fiber/v2"
)

func Home(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": constants.STATUS_SUCCESS,
		"name":   configs.GetInstance().Appconfig.Name,
	})
}
