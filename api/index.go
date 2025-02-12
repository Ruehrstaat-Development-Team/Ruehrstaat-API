package api

import (
	"ruehrstaat-backend/api/auth"
	"ruehrstaat-backend/api/carrier"
	"ruehrstaat-backend/api/public"
	"ruehrstaat-backend/api/users"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(router *gin.RouterGroup) {
	api := router.Group("/v1")

	api.GET("/health", healthCheck)

	auth.RegisterRoutes(api)
	users.RegisterRoutes(api)
	public.RegisterRoutes(api)
	carrier.RegisterRoutes(api)
}

func healthCheck(c *gin.Context) {
	c.JSON(200, gin.H{"message": "OK"})
}
