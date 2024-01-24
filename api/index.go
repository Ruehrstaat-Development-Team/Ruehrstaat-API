package api

import (
	"ruehrstaat-backend/api/auth"
	"ruehrstaat-backend/api/users"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(router *gin.RouterGroup) {
	api := router.Group("/v1")

	auth.RegisterRoutes(api)
	users.RegisterRoutes(api)
}
