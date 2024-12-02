package main

import (
	"os"

	"github.com/Adventure-Inc/users-backend/middleware"
	"github.com/Adventure-Inc/users-backend/routers"
	"github.com/gin-gonic/gin"
	"github.com/krishpranav/golang-management/routers"
)

func main() {

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	router := gin.New()
	router.Use(gin.Logger())
	routers.UserRoutes(router)
	router.Use(middleware.Authentication())

	router.Run(":" + port)

}
