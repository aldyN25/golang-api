package jwt

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/aldyN25/go-fiber-rest/app/configs"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
)

func ExtractClaims(secret, tokenStr string) (jwt.MapClaims, error) {
	hmacSecret := []byte(secret)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return hmacSecret, nil
	})

	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid JWT Token")
}

func TokenVerify() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		configs := configs.GetInstance()
		token := ctx.GetReqHeaders()["Authorization"]
		parts := strings.Split(token, " ")
		if token == "" {
			return ctx.Status(401).JSON(fiber.Map{
				"status":  "failed",
				"message": "Unauthorized",
				"data":    nil,
			})
		}

		claims, err := ExtractClaims(configs.Jwtconfig.Secret, parts[1])
		if err != nil {
			return ctx.Status(401).JSON(fiber.Map{
				"status":  "failed",
				"message": "Unauthorized",
				"data":    nil,
			})
		}
		result := map[string]string{}
		encoded, _ := json.Marshal(claims)
		json.Unmarshal(encoded, &result)
		for key, val := range result {
			ctx.Set(key, val)
			ctx.Locals(key, val)
		}
		return ctx.Next()
	}
}

func Authorization(role []string) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		configs := configs.GetInstance()
		token := strings.Split(ctx.Get("Authorization"), " ")
		claim, err := ExtractClaims(configs.Jwtconfig.Secret, token[1])
		if err != nil {
			return ctx.Status(401).JSON(fiber.Map{
				"status":  "failed",
				"message": "Unauthorized",
				"data":    nil,
			})
		}

		mapRole := make(map[int]string)
		for i, v := range role {
			mapRole[i] = v
			if claim["role"] == mapRole[i] {
				ctx.Next()
				return nil
			}
		}
		return ctx.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"message": errors.New("anda tidak memiliki akses"),
			"data":    nil,
		})
	}
}
