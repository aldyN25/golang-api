package jwt

import (
	"time"

	"github.com/aldyN25/go-fiber-rest/app/configs"
	"github.com/aldyN25/go-fiber-rest/app/models"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/golang-jwt/jwt"
)

func CreateToken(user *models.User) string {
	configs := configs.GetInstance()

	claims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Duration(configs.Jwtconfig.Expired) * time.Second).Unix(),
	}

	unsignToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, _ := unsignToken.SignedString([]byte(configs.Jwtconfig.Secret))

	return token
}

type Token struct {
	Data interface{}
	*jwt.StandardClaims
}

func GenerateToken(user *models.User) (*string, error) {
	configs := configs.GetInstance()

	claims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Duration(configs.Jwtconfig.Expired) * time.Second).Unix(),
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)
	result, err := token.SignedString([]byte(configs.Jwtconfig.Secret))
	if err != nil {
		return nil, err
	}
	return &result, err
}
func GetUserId(c *fiber.Ctx) (UserId uuid.UUID) {
	user := c.Locals("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	UserId, _ = uuid.Parse(claims["user_id"].(string))
	return
}
